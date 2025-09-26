import socket

HOST = "127.0.0.1"   # localhost
PORT = 8080          # change if busy

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Listening on {HOST}:{PORT} ...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            chunks = []
            while True:
                buf = conn.recv(4096)
                if not buf:
                    break
                chunks.append(buf)

            data = b"".join(chunks)
            print(f"\nReceived {len(data)} bytes:")
            try:
                print(data.decode("utf-8", errors="replace"))
            except Exception:
                print(data)

            print("\nConnection closed. Server exiting.")

if __name__ == "__main__":
    main()
