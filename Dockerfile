FROM openpolicyagent/opa:0.37.0-dev-static

COPY ./policies /policies
ENTRYPOINT ["/opa"]
CMD ["run", "--skip-version-check", "--ignore=.*", "--server", "--log-level=debug", "/policies"]