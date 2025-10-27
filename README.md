# DNS Forwarding Server

A DNS forwarding server written in Go that parses DNS packets, handles name compression, and forwards queries to upstream resolvers.

## Features

- Parse DNS messages (header, question, answer sections)
- Handle DNS name compression
- Forward single and multiple DNS queries to upstream resolvers
- Merge responses from multiple queries
- Support A record queries

## Architecture

```
app/
  main.go          # UDP server and CLI
message/
  message.go       # DNS message parsing and forwarding
header/
  header.go        # DNS header parsing
question/
  question.go      # Question section parsing
answer/
  answer.go        # Answer section parsing
```

## Usage

Run the server with a resolver:

```bash
./your_program.sh --resolver 8.8.8.8:53
```

The server listens on port 2053 and forwards DNS queries to the specified resolver.

## Implementation Details

- **Compression Support**: Handles DNS name compression via pointers (2-byte offsets)
- **Query Splitting**: Automatically splits multi-question queries when necessary
- **Response Merging**: Combines responses from split queries
- **Flag Preservation**: Maintains original OPCODE, RD, and transaction ID values
