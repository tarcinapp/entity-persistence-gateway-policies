FROM openpolicyagent/opa:1.8.0-static

COPY ./policies /policies

# Run tests during build
RUN ["/opa", "test", "/policies", "-v"]

ENTRYPOINT ["/opa"]
CMD ["run", "--skip-version-check", "--ignore=.*", "--server", "--log-level=debug", "/policies"]
CMD ["run", "--server", "--ignore=*_test.rego", "/policies"]