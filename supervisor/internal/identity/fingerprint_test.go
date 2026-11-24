package identity

import "testing"

func TestParse(t *testing.T) {
	dockerCg := "0::/docker/3f0c1c6f0e2d4a2f8f5c3c9d0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e\n"
	cid, pod := Parse(dockerCg, "")
	if cid != "3f0c1c6f0e2d4a2f8f5c3c9d0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e" || pod != "" {
		t.Fatalf("docker cgroup v1: %q %q", cid, pod)
	}
	// cgroup v2 docker: cgroup says 0::/ ; mountinfo carries the container path
	mi := "1234 1000 0:60 / / rw - overlay overlay rw\n2000 1234 8:1 /var/lib/docker/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
	cid, _ = Parse("0::/\n", mi)
	if cid != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("docker cgroup v2 via mountinfo: %q", cid)
	}
	// kubernetes (containerd): pod uid in the kubelet volume path, container id in the cgroup scope
	k8sCg := "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1b2c3d4e_5f60_4a7b_8c9d_0e1f2a3b4c5d.slice/cri-containerd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope\n"
	k8sMi := "500 400 0:70 / /var/run/secrets/kubernetes.io/serviceaccount ro - tmpfs tmpfs rw\n501 400 8:1 /var/lib/kubelet/pods/1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d/etc-hosts /etc/hosts rw - ext4 /dev/sda1 rw\n"
	cid, pod = Parse(k8sCg, k8sMi)
	if cid != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || pod != "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Fatalf("k8s: %q %q", cid, pod)
	}
	// pod uid only from the cgroup path (no kubelet mounts visible)
	_, pod = Parse(k8sCg, "")
	if pod != "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Fatalf("k8s pod uid from cgroup: %q", pod)
	}
}

func TestRuntime(t *testing.T) {
	if (Fingerprint{PodUID: "u"}).Runtime() != "k8s" || (Fingerprint{ContainerID: "c"}).Runtime() != "docker" {
		t.Error("type detection")
	}
}
