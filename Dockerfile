# Use a base image with minimal tools
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y wget tar build-essential \
    libgmp-dev flex bison

# Install Go 1.22.3
RUN wget https://golang.org/dl/go1.22.3.linux-arm64.tar.gz
RUN tar -C /usr/local -xzf go1.22.3.linux-arm64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Download and install pbc
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar -xzf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure \
    && make \
    && make install

# Set the library path
ENV LD_LIBRARY_PATH="/usr/local/lib"

# Set the working directory
WORKDIR /app

# Set CGO flags
ENV CGO_CFLAGS="-I/usr/local/include/pbc -I/usr/include"
ENV CGO_LDFLAGS="-L/usr/local/lib -lpbc -lgmp"

# Copy go mod and sum files
COPY go.mod ./
COPY go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source from the current directory to the working directory inside the container
COPY . .

# Build the Go app
RUN go build -o main ./cmd/decryption-service

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]
