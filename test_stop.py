import pytest
import socket
from Cryptodome.Hash import SHA256
from server import stop_client
from server import hash256


# Socket for Testing Purposes:
testingSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
testingSocket.bind(("127.0.0.1",1235))
#testingSocket.connect(("127.0.0.1",1234))

# SHA256 Hash:
keysha = hash256([12,16,15,444])

result = stop_client(testingSocket,{ "op": "STOP", "shasum": keysha })

assert isinstance(result, dict)
assert "op" in result
assert "status" in result

assert result["status"] == False
assert result["op"] == "STOP"

print("Everything's working alright!")