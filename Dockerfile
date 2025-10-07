FROM openpolicyagent/opa:1.9.0-static

COPY ./policies /policies

# Run tests during build
RUN ["/opa", "test", "/policies", "-v"]

ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--ignore=*_test.rego", "/policies"]