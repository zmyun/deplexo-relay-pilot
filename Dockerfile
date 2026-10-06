FROM python:3.13-slim
WORKDIR /app
COPY vless_bridge.py .
RUN useradd -m -u 10001 relay && chown relay:relay /app/vless_bridge.py
USER relay
ENV PORT=3000
EXPOSE 3000
CMD ["python", "vless_bridge.py"]
