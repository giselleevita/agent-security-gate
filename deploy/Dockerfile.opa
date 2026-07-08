FROM openpolicyagent/opa:0.65.0-static
COPY policies /policies
CMD ["run", "--server", "--addr", ":8181", "/policies"]
