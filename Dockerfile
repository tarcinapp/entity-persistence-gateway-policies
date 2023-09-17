FROM openpolicyagent/opa:0.24.0

COPY ./policies /policies
ENTRYPOINT ["/opa"]
CMD ["run", "--skip-version-check", "--ignore=.*", "--server", "--log-level=debug", "/policies"]