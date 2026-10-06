# App that goes unhealthy 6s after its FIRST start and stays healthy after a
# restart (marker file survives an in-place restart). Exercises: grace,
# threshold, unhealthy_for, restart, ready flipping 200 -> 503 -> 200.
FROM public.ecr.aws/docker/library/python:3.12-slim
COPY app.py /app.py
COPY fleetwide.yaml /fleetwide/fleetwide.yaml
EXPOSE 8080
CMD ["python", "/app.py"]
