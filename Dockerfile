FROM python:3.13-slim
WORKDIR /app
COPY relay.py .
RUN useradd -m -u 10001 relay && chown relay:relay /app/relay.py
USER relay
ENV PORT=3000
EXPOSE 3000
CMD ["python", "relay.py"]
