FROM python:3.12-alpine
WORKDIR /opt/twin
COPY . .
CMD ["python3", "tests/test_twin.py", "-v"]
