FROM alpine:3.21.2 AS final

WORKDIR /app    

COPY ./docker/run_client.sh .

# sending ping to the server
CMD [ "./run_client.sh" ]
