#!/usr/bin/python3

""" /// Dependencies [START] /// """

import re
import os
import sys
import socket
#import json
import base64
from common_comm import send_dict, recv_dict, sendrecv_dict
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256

""" /// Dependencies [END] /// """










""" /// Security Methods [START] /// """

""" Data Encryption """
# This function encrypts data. Parameters: KEY , DATA.
def encrypt_intvalue (cipherkey, data):
	cipher = AES.new (cipherkey, AES.MODE_ECB)
	data = cipher.encrypt (bytes("%16d" % (data), "utf-8"))
	data_tosend = str (base64.b64encode (data), "utf-8")
	return data_tosend
# Returns int data encrypted in a 16 bytes binary string encoded in base64.


""" Data Decryption """
# This function decrypts data. Parameters: KEY , DATA.
def decrypt_intvalue (cipherkey, data):
	cipher = AES.new (cipherkey, AES.MODE_ECB)
	dados = base64.b64decode (data)
	dados = cipher.decrypt (dados)
	dados = int (str (dados, "utf8"))
	return dados
# Returns int data decrypted from a 16 bytes binary strings encoded in base64


""" 256-Bit Hashing """
# Hash function that generates a fixed-size output of 256 bits.
def hash256(numbers):
	# Converts the list of numbers to a string, concatenating them (...)
	# (...) without any separator.
	numbers_str = "".join(str(n) for n in numbers)
	h = SHA256.new()
	h.update(numbers_str.encode("utf-8"))
	sintese = h.digest()
	return sintese
# Returns an hexadecimal representation of the hash

""" /// Security Methods [END] /// """










""" /// Specific Validation Methods [START] /// """

""" User Input Validation """
# This function validates the user's input to prevent errors.
# NOTE: It's used in the 'Main-Menu' and 'Sub-Menu'.
def get_menu_choice(inicio, fim):
    while True:
        try:
            choice = int(input("\033[34m"+"INFO: "+"\033[39m"+"Option: "))
            if choice not in range(inicio,fim+1):
                raise ValueError
            return choice
        except ValueError: 
            print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid Input! Please try again...")


""" Server -> Client Message Validation """
# This function verifies if a response from the server is valid.
def validate_response (client_sock, response):
	if not response["status"]:
		print ("\033[31m"+"ERROR: "+"\033[39m"+response["error"])
		client_sock.close()
		sys.exit(3)
# Closes the program if there's an error.


""" 'QUIT' Operation Method """
# This function handles the QUIT Operation.
def quit_action (client_sock,flag=False):
	request = {"op": "QUIT"}
	response = sendrecv_dict(client_sock, request) 
	if "status" in response:
		validate_response(client_sock, response)
		if (not flag):
			client_sock.close()
			sys.exit(4)
	else:
		print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid Server Response!")


""" 'ID' Validation """
# This function validates if the 'ID' is valid.
def validate_id(id):
	if not id:
		print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid ID! Closing the program...")
		sys.exit(1)
	return id
# If not, prints an error message and exits with 'Code 1'.


""" 'IP' Validation """
# This function validates if  the 'IP' is valid (should be XXXX.XXXX.XXXX.XXXX, w/ x=>int() from 0,255).
# NOTE: This function uses RegEx expressions.
def validate_host(ip):
	if(ip !="localhost"):
		regex =  "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
		if(not(re.search(regex, ip))):
			print("\033[31m"+"ERROR:  "+"\033[39m"+"Invalid IPv4! Closing the program...")
			sys.exit(1)
	return ip
# Returns the IP if valid, else exits with 'Code 1'.


""" 'PORT' Validation """
# This function validates if a port is an integer and it's between 1 and 65535.
def validate_port(port):
	try:
		port = int(port)
		if port < 1 or port > 65535:
			print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid PORT number! Must be within [1,65534]. Closing the program...")
			sys.exit(1)
		return port
	except ValueError: 
		print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid PORT number! Must be within [1,65534]. Closing the program...")
		sys.exit(1)
# If invalid, the function should print an error message and exits with "Code 1".


""" /// Specific Validation Methods [END] /// """










""" /// User-Interactible Logic [START] /// """

# Outcomming Message Structure:
	# { op = "START", client_id, [cipher] }
	# { op = "QUIT" }
	# { op = "NUMBER", number }
	# { op = "STOP", [shasum] }
	# { op = "GUESS", choice }

# Incomming Message Structure:
	# { op = "START", status }
	# { op = "QUIT" , status }
	# { op = "NUMBER", status }
	# { op = "STOP", status, value }
	# { op = "GUESS", status, result }

""" Main-Menu """
# This function is the Main-Menu.
# NOTE: This is the first menu the user interacts with.
def run_client(client_sock, client_id):
		choice = 0
		control = False
		cipherkey = None
		while True :
			print("\033[33m"+"MENU: "+"\033[39m"+"1. START")
			print("\033[33m"+"MENU: "+"\033[39m"+"2. EXIT")
			choice = get_menu_choice(1,3)
			if choice == 1: # If option was start:
				request = {"op": "START","client_id": client_id}


				""" /// Communication Management Settings [START] /// """

				print("\n\033[34m"+"INFO: "+"\033[39m"+"Before starting the game we need to set some settings!")

				""" Data Encryption (AES-256) """
				# NOTE: Here the user has the choice to enable data encryption.
				print("\033[34m"+"INFO: "+"\033[39m"+
					"Enabling Data Encryption ensures no other beyond you and the server are able to read the messages exchanged.")
				while (True):
					security = input("\033[34m"+"INFO: "+"\033[39m"+"Message Encryption: [Y/n]")
					if security.upper() == "Y": # Creating a cipherkey 
						cipherkey = os.urandom(16)
						cipherkey_tosend = str(base64.b64encode (cipherkey), "utf-8")
						request["cipher"] = cipherkey_tosend 
						response = sendrecv_dict(client_sock, request) 
						validate_response (client_sock, response)
						break
					elif (security.upper() == "N"):
						response = sendrecv_dict(client_sock, request) 
						validate_response (client_sock, response)
						break
					else:
						print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid Input! Please try again...")

				""" Data Control (AES-256) """
				# NOTE: Here the user has the choice to enable data control.
				print("\033[34m"+"INFO: "+"\033[39m"+
					"Enabling Data Control (Tamper Protection) ensures the communications between you and the server are legit.")
				while(True):
					controlData = input("\033[34m"+"INFO: "+"\033[39m"+"Data Control: [Y/n]")
					if controlData.upper() == "Y":
						control=True
						break
					elif (controlData.upper() == "N"):
						break
					else:
						print("\033[31m"+"ERROR: "+"\033[39m"+"Invalid Input! Please try again...")

				""" /// Communication Management Settings [END] /// """

				print("\n\033[34m"+"INFO: "+"\033[39m"+"The connection has been succesfully established with those settings!")
				print("\033[34m"+"INFO: "+"\033[39m"+"Brief description of the game:\n")
				print("The goal of this game is to send whole numbers (integers) to the server"
					+ " and guess which number is chosen randomly by the server.\nThe server can choose one of the following numbers:"
					+ " the first number in the list, the last number in the list, the minimum number, the maximum number or the median number (if the list has an even number of elements).\n"
					+ "You win the game if you guess the number chosen by the server. Good luck! Let's get this game started...\n")
				subMenu(client_sock, client_id,cipherkey,control)

			elif choice ==2:
				print("\033[34m"+"INFO: "+"\033[39m"+"Goodbye! =)")
				sys.exit(0)
# If the user chooses the option 2., then the program is closed with 'Code 0'.
# Else, if option 1., starts the Sub-Menu (see below).


""" Sub-Menu """
# This is the Menu the user interacts with when he selects 1.START from the Main-Menu.
# NOTE: If the user chooses to send numbers, they will be prompted to input values until they type "STOP".
# NOTE: The function then sends the list of values to the server and waits for a response.
# NOTE: If the user has enabled the control feature, the function will hash the list of values and send the hash to the server.
def subMenu(client_sock,client_id, cipherkey, control):
	choice = 0
	while True:
		print("\033[33m"+"MENU: "+"\033[39m"+"1. RETURN TO THE PREVIOUS MENU")
		print("\033[33m"+"MENU: "+"\033[39m"+"2. START SENDING NUMBERS TO THE SERVER")
		choice = get_menu_choice(1,2)
		if choice == 1: # If option to return.
			quit_action(client_sock,flag=True)
			run_client(client_sock, client_id)	
		else:
			print("\033[34m"+"INFO: "+"\033[39m"+"To stop sending numbers, write 'STOP'.")
			print("\033[34m"+"INFO: "+"\033[39m"+"To give up (stop gaming), write 'QUIT'. You can quit at any time, but the simulation will be without effect.")
			stop = False
			list_valores = []
			while not stop:
				data = input ("\033[33m"+"GAME: "+"\033[39m"+"Value: ")
				if (data==""): continue
				if data.upper() == "QUIT":
					if client_sock is None:
						print("\033[31m"+"ERROR: "+"\033[39m"+"No connection to server!")
					else:
						quit_action(client_sock)
						stop = True
				elif data.upper() == "STOP":
					stop = True
				if (data[0] == '-' and data[1:].isdigit()) or data.isdigit() :
					if cipherkey is None :
						request = {"op": "NUMBER", "number":int(data) }
					else:
						request = {"op": "NUMBER", "number": encrypt_intvalue(cipherkey,int(data))}
					response = sendrecv_dict (client_sock, request)
					validate_response (client_sock, response)
					list_valores.append(int(data))
				else: 
					continue
			if control:
				hash_value = hash256(list_valores)
				request = { "op": "STOP", "shasum": str (base64.b64encode(hash_value), "utf-8")}
			else:
				request = { "op": "STOP" }
			response = sendrecv_dict (client_sock, request)
			validate_response (client_sock, response)
			# Indicates the numbers sent to the server and the number received from the server.
			print ("\033[33m"+"GAME (by CLIENT):"+"\033[39m"+"Array of Numbers sent by the Client: {}".format(list_valores))
			if cipherkey != None:
				print("\033[33m"+"GAME (by SERVER):"+"\033[39m"+"Value Received: %d" % (decrypt_intvalue(cipherkey,response["value"])))
			else:
				print("\033[33m"+"GAME (by SERVER):"+"\033[39m"+"Value Received: %d" % (response["value"]))
			guess_action(client_sock,client_id)
# Starts the 'Gaming' Logic (see below).


""" 'Gaming' Logic """
# This is the game logic after the user has sent all the numbers to the server (...)
# (...) from the previous menu (Sub-Menu).
def guess_action(client_sock, client_id):
	# Define a list of possible answers.
	resposts = ("min" , "max" , "first","last", "median")
	# Prompt the user to select a characteristic from the menu-list.
	print("\033[34m"+"INFO: "+"\033[39m"+"After sending the data, you must guess the attribute value that the server has chosen.")
	print("\033[34m"+"INFO: "+"\033[39m"+"Select a characteristic from the following menu-list:")
	print("\033[34m"+"INFO: "+"\033[39m"+"1. ”min” | 2. ”max” | 3. ”first” | 4. ”last” | 5. ”median”")
	index = get_menu_choice(1,5)
	# Creates the message to be sent to the server at the user's choice.
	request = { "op": "GUESS", "choice": resposts[index-1]}
	# Send the message and wait for the server to respond.
	response = sendrecv_dict (client_sock, request)
	# Validates the response received from the server.
	validate_response(client_sock, response)
	# Gets the result of user guessing.
	result = response["result"]
	# Displays the result and returns to the main menu.
	print("\033[33m"+"GAME: "+"\033[39m"+f"Your guess is... {result}!")
	print("\033[33m"+"GAME: "+"\033[39m"+"Congrats for the run! Now returning you to the main-menu...")
	run_client(client_sock, client_id)
# Returns to the Main-Menu.


""" /// User-Interactible Logic [END] /// """










""" /// Program Management [START] /// """

""" Python's Main Method """
# This is the first method the program runs.
# Manages the start of the Client.
def main():

	# Validates the number of arguments from sys.argv.
	if len(sys.argv) < 3 or len(sys.argv) > 4:
		print("\033[31m"+"ERROR: "+"\033[39m"+"Usage -> python client.py CLIENT_NAME SERVER_PORT SERVER_IP")
		sys.exit(1)
	# Prints an error message and exit with 'Code 1' if misused.

	# From sys.argv, gets the PORT Number.
	id = validate_id(sys.argv[1])
	port = validate_port(sys.argv[2])

	# From sys.argv, gets the Hostname.
	# NOTE: Can be 'localhost' or in IPV4 format.
	if len(sys.argv) == 4:
		hostname = validate_host(sys.argv[3])
	else:
		hostname = "localhost"

	# Starts the Client Socket and establishes the connection to the Server.
	client_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	client_socket.bind(("0.0.0.0", 0))
	client_socket.connect ((hostname, port))
	run_client (client_socket, sys.argv[1])

	# If everything went well (without errors), closes the Client Socket and (...)
	# (...) terminates the Client Program.
	client_socket.close ()
	sys.exit (0)


""" Standard Python Stuff """
if __name__ == "__main__":
    main()


""" /// Program Management [END] /// """