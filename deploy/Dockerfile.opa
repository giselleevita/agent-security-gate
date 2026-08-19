FROM openpolicyagent/opa:1.19.1-static@sha256:32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32
COPY policies /policies
CMD ["run", "--server", "--addr", ":8181", "/policies"]
