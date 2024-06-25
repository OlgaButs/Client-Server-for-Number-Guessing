#!/usr/bin/python3

""" /// Dependencies [START] /// """

import sys
import socket
import select
#import json
import base64
import csv
import random
from common_comm import send_dict, recv_dict, sendrecv_dict
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256

""" /// Dependencies [END] /// """










""" /// Security Methods [START] /// """

""" Data Encryption """
# This function encrypts data. Parameters: KEY , DATA.
def encrypt_intvalue (client_id, data):
	cipherkey = users[client_id]["cipher"]
	cipherkey = base64.b64decode(cipherkey)
	cipher = AES.new(cipherkey, AES.MODE_ECB)
	data = cipher.encrypt (bytes("%16d" % (data), "utf-8"))
	data_tosend = str (base64.b64encode (data), "utf-8")
	return data_tosend
# Returns int data encrypted in a 16 bytes binary string encoded in base64.


""" Data Decryption """
# This function decrypts data. Parameters: KEY , DATA.
def decrypt_intvalue (client_id, data):
	cipherkey = base64.b64decode(users[client_id]["cipher"])
	cipher = AES.new (cipherkey, AES.MODE_ECB)
	dados = base64.b64decode (data)
	dados = cipher.decrypt (dados)
	dados = int(str(dados, "utf8"))
	return dados
# Returns int data decrypted from a 16 bytes binary strings encoded in base64


""" 256-Bit Hashing """
# Hash function that generates a fixed-size output of 256 bits.
def hash256(numbers):
	numbers_str ="".join(str(n) for n in numbers)
	h = SHA256.new()
	h.update(numbers_str.encode("utf-8"))
	_hash = h.digest()
	return _hash
# Returns an hexadecimal representation of the hash

""" /// Security Methods [END] /// """










""" /// Specific Validation Methods [START] /// """

# Dictionary with client information.
users = {}


""" Client Remove """
# This function removes a client from the 'users' dictionary.
def clean_client (client_sock):
	client_id = find_client_id (client_sock)
	if client_id != None:
		print ("\033[34m"+"INFO: "+"\033[39m"+"Client %s removed from the dictionary!" %client_id)
		del users[client_id]
# NOTE: This obtains the client_id from his socket and deletes the user from the dictionary.


""" 'users' Dictionary Finder """
# This function finds clients in 'users'.
def find_client_id (client_sock):
    for client_id, sock in users.items():
        if sock["socket"] == client_sock:
            return client_id
    return None
# Return the client_id of a socket or None.


""" 'IP' Validation """
# This function validates if  the 'IP' is valid (should be XXXX.XXXX.XXXX.XXXX, w/ x=>int() from 0,255).
def validate_port(port):
	if not port.isdigit():
		print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid PORT Number! Must be within [1,65534]. Closing the program...")
		sys.exit(1)
	elif int(port) < 1 or int(port) > 65535:
		print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid PORT Number! Must be within [1,65534]. Closing the program...")
		sys.exit(1)
	return int(port)
# Returns the IP if valid, else exits with 'Code 1'.

""" /// Specific Validation Methods [END] /// """










""" /// 'Operation' Logic Management [START] /// """

# Incomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP", [shasum] }
# { op = "GUESS", choice }
#
# Outcomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, value }
# { op = "GUESS", status, result }


""" User Input Decode using the Specified Protocol (above) """
# This method decodes the received message from the user and acts accordingly.
def new_msg (client_sock):
	request = recv_dict (client_sock)
	# print( "Command: %s" % (str(request)) )
	op = request["op"]
	if op == "START":
		response = new_client (client_sock, request)
	elif op == "QUIT": # 
		response = quit_client (client_sock, request)
	elif op == "NUMBER": # 
		response = number_client (client_sock, request)
	elif op == "STOP": # 
		response = stop_client (client_sock, request)
	elif op == "GUESS": # 
		response = guess_client (client_sock, request)
	else:
		response = { "op": op, "status" : False, "error": "Operação inexistente" }
	# print (response)
	send_dict (client_sock, response )


""" Operation START """
# This method creates a new client.
# NOTE: 1. Detects the client in the request.
# NOTE: 2. Verifies the appropriate conditions for executing this operation.
# NOTE: 3. Processes the client in the dictionary.
def new_client (client_sock, request):
	client_id = request["client_id"]
	cipherkey = request.get("cipher", None)
    # check if client ID already exists
	if client_id in users:
		response = { "op": "START", "status": False, "error": "Cliente existente" }
	else:
	# add new client to dictionary
		users[client_id] = {"socket": client_sock, "cipher": cipherkey,  "number": []}
		response = { "op": "START", "status": True }
		print ("\033[34m"+"INFO: "+"\033[39m"+"Client {0} added to the dictionary!".format(client_id))
	return response
# Returns a response message with or without an error message.


""" Operation QUIT """
# This method processes the QUIT Operation.
# NOTE: 1. Registers the QUIT action by the user.
# NOTE: 2. Removes the client from the dictionary.
def quit_client (client_sock, request):
	# obtain the client_id from his socket
	client_id = find_client_id(client_sock)
	# verify the appropriate conditions for executing this operation
	if client_id is None:
		return {"op": "QUIT", "status": False, "error": "Cliente inexistente"}
	else:# eliminate client from dictionary using the function clean_client
		clean_client(client_sock)
	# return success response
	print("\033[34m"+"INFO: "+"\033[39m"+"Client "+client_id+" has Quit.")
	return {"op": "QUIT", "status": True}
# Processes the report file with the QUIT result.


""" Operation NUMBER """
# This method registers the number sent by the client (...)
# (...) in regards to the 'gaming' component of this program.
# NOTE: 1. Obtains the client_id from his socket.
# NOTE: 2. Verifies the appropriate conditions for executing this operation.
def number_client (client_sock, request):
	client_id = find_client_id(client_sock)
	if client_id is None:
		return {"op": "NUMBER", "status": False, "error": "Cliente inexistente"}
    # obtain the number from the request
	number = request.get("number")
	if number is None:
		return {"op": "NUMBER", "status": False, "error": "Número inválido"}
	cipherkey = users[client_id].get("cipher")
	# update the client's number list
	if cipherkey == None :
		users[client_id]["number"].append(number)
	else:
		n = decrypt_intvalue(client_id, number)
		users[client_id]["number"].append(n)
    # return success response
	print("\033[34m"+"INFO: "+"\033[39m"+"Client "+client_id+" has sent a number.")
	return {"op": "NUMBER", "status": True}
# Returns a response message with or without an error message.


""" Operation STOP """
# This method implements the operation STOP.
# It's triggered by the client -- when he wishes to stop sending more numbers to the server.
# NOTE: 1. Obtains the client_id from his socket.
# NOTE: 2. Verifies the appropriate conditions for executing this operation.
# NOTE: 3. Randomly generates a value to return using the function generate_result.
# NOTE: 4. Processes the report file with the result.
def stop_client (client_sock, request):
	shasum = request.get("shasum", False)
	client_id = find_client_id(client_sock)
	response = None
	if not client_id:
		return {"op": "STOP", "status": False, "error": "Cliente inexistente"}
	if shasum: 
		shasum = base64.b64decode(shasum)
		if shasum != hash256(users[client_id]["number"]):
			return { "op": "STOP", "status": False, "error": "Síntese inconsistente" }
	if not users[client_id]["number"]:
		return {"op": "STOP", "status": False, "error": "Dados insuficientes"}
	else:
		value, result = generate_result(users[client_id]["number"])
		users[client_id]["solution"] = result
		update_file(client_id, len(users[client_id]["number"]), result)
		if users[client_id].get("cipher") != None:
			response = {"op": "STOP", "status": True, "value": encrypt_intvalue(client_id, value)}
		else:
			response = {"op": "STOP", "status": True, "value": value}
		print("\033[34m"+"INFO: "+"\033[39m"+"Client {0} has stoped sending numbers.".format(client_id))
	return response
# Returns a response message with the result or an error message.


""" Operation GUESS """
# This method suports the 'guessing' operation from the client (...)
# (...) in regards to the 'gaming' component of this program.
def guess_client (client_sock, request):
	# Obtain the client ID from his socket
    client_id = find_client_id(client_sock)
    # Verify the appropriate conditions for executing this operation
    if client_id is None:
        # If the client is not active, return an error response
        return {"op": "GUESS", "status": False, "error": "Cliente inexistente"}
    # Get the client's guess
    guess = request.get("choice", "")
    # Check if the guess matches the result
    if guess in users[client_id]["solution"]:
        # If the guess is correct, return a success response
        clean_client(client_sock) # eliminate client from dictionary
        print("\033[34m"+"INFO: "+"\033[39m"+"Client has guessed the number correctly!")
        return {"op": "GUESS", "status": True, "result": True}
    else:
        clean_client(client_sock) # eliminate client from dictionary
        # If the guess is incorrect, return a failure response
        print("\033[34m"+"INFO: "+"\033[39m"+"Client has guessed the number incorrectly.")
        return {"op": "GUESS", "status": True, "result": False}
# Returns a response message with the result or an error message.


""" Select a Number """
# This is a Auxiliary Function to select a number from the list received by the user.
# This is part of the 'gaming' component of this program.
def generate_result (list_values):
	if len(list_values) % 2 == 1: test = 4
	else : test = 3
	#
	minimal = min(list_values)
	maximal = max(list_values)
	first = list_values[0]
	last = list_values[-1]
	#
	choice = random.randint (0, test)
	if choice == 0:
		if minimal == first: return first, ["min", "first"]
		elif maximal == first: return first, ["max", "first"]
		else: return first, ["first"]
	elif choice == 1:
		if minimal == last: return last, ["min", "last"]
		elif maximal == last: return last, ["max", "last"]
		else: return last, ["last"]
	elif choice == 2:
		if minimal == first: return first, ["min", "first"]
		elif minimal == last: return last, ["min", "last"]
		else: return minimal, ["min"]
	elif choice == 3:
		if maximal == first: return first, ["max", "first"]
		elif maximal == last: return last, ["max", "last"]
		else: return maximal, ["max"]
	elif choice == 4:
		#listsort = list_values.sort()
		#median = listsort[len(listsort) // 2]
		list_values.sort()
		median = list_values[len(list_values) // 2]
		if median == first: return first, ["median", "first"]
		elif median == last: return last, ["median", "last"]
		else: return median, ["median"]
	else:
		return None
# Returns a int value and a list of description strings identifying the (...)
# (...) characteristic of the chosen value.

""" /// 'Operation' Logic Management [END] /// """










""" /// External File Logging (CSV) [START] /// """

""" File Creation """
# This method creates a CSV with a header.
def create_file ():
	with open("result.csv", "w", newline="") as csvfile:
		columns = ["client_id", "number_of_numbers", "guess"]
		fw = csv.DictWriter (csvfile, delimiter=",", fieldnames=columns)
		fw.writeheader()
		print("\033[34m"+"INFO: "+"\033[39m"+"The logging file has been created!")


""" File Update """
# This method updates the created file (above) with new data.
def update_file (client_id, size, guess):
	try:
		with open("result.csv", "a", newline="") as csvfile:
			writer = csv.writer(csvfile)
			writer.writerow([client_id, size, guess])
			print("\033[34m"+"INFO: "+"\033[39m"+"Logging file updated!")
	except Exception as e:
		print("\033[31m"+"ERROR: "+"\033[39m"+f"Error updating file \"ficheiro.csv\" : {e}")

""" /// External File Logging (CSV) [END] /// """










""" /// Program Management [START] /// """

""" Python's Main Method """
# This is the first method the program runs.
# Manages the start of the Client.
def main():
	
	# Validates the number of arguments and eventually prints an error message (...)
	# (...) and exits with 'Code 1' if misused.
	if len(sys.argv)!=2:
		print("\033[31m"+"ERROR: "+"\033[39m"+"Usage -> python server.py SERVER_PORT")
		sys.exit(1)

	# Verifies the type of arguments and eventually prints error message (...)
	# (...) and exits with 'Code 1' if something is wrong.
	port = validate_port(sys.argv[1])

	server_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	print("\033[34m"+"INFO: "+"\033[39m"+"Server Socket Instanciated.")
	server_socket.bind (("127.0.0.1", port))
	print("\033[34m"+"INFO: "+"\033[39m"+"Server Socket Binded to '127.0.0.1:"+str(port)+"'.")
	server_socket.listen ()
	clients = []
	create_file ()

	while True:
		try:
			available = select.select ([server_socket] + clients, [], [])[0] # + list(sys.stdin)
		except ValueError:
			# Sockets may have been closed, check for that.
			for client_sock in clients:
				if client_sock.fileno () == -1: clients.remove(client_sock)#client_sock.remove(client) # Closed.
			continue # Reiterate select.
		for client_sock in available:
			# New client?
			if client_sock is server_socket:
				newclient, addr = server_socket.accept ()
				clients.append (newclient)
				print("\033[34m"+"INFO: "+"\033[39m"+"Client "+str(addr)+" has Connected.")
			# Or an existing client.
			else:
				temp = find_client_id(client_sock)
				# See if client sent a message.
				if len (client_sock.recv (1, socket.MSG_PEEK)) != 0:
					# client socket has a message.
					##print ("server" + str (client_sock))
					new_msg (client_sock)
					if temp!=None: print("\033[34m"+"INFO: "+"\033[39m"+"Message Received from Client "+str(find_client_id(client_sock))+".")
					else: print("\033[34m"+"INFO: "+"\033[39m"+"Message Received from a Client.")
				else: # Or just disconnected.
					clients.remove (client_sock)
					clean_client (client_sock)
					client_sock.close ()
					if temp!=None: print("\033[34m"+"INFO: "+"\033[39m"+"Client {0} has Disconnected.".format(temp))
					else: print("\033[34m"+"INFO: "+"\033[39m"+"A Client has Disconnected.")
					break # Reiterate select.

""" Standard Python Stuff """
if __name__ == "__main__":
	main()

""" /// Program Management [END] /// """