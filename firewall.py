# Uses pandas library
import pandas as pd
import sys


class Firewall:

	def __init__(self, path):
		# Initialization
		self.flag = True
		# Stores rules in a data frame
		self.df_rules = pd.read_csv(path, header=None)

	# Method for cleaning and checking valid test cases
	def preprocess(self,x):
		# Input with whitespaces at the left or right side, and string in double quotes - "inbound" accepted
		y = [a.strip() for a in x.split(',')]
		y = [a.strip('\"') for a in y]

		# if direction is not one of these, set the flag to false -  No more processesing required
		if y[0] != "inbound" and y[0] != "outbound":
			print("Invalid direction")
			self.flag = False

		# if protocol is not one of these, set the flag to false -  No more processesing required
		if y[1] != "tcp" and y[1] != "udp":
			print("Invalid Protocol - ",end = "")
			self.flag = False
		else:
			self.flag = True
		return y

	# Method to validate test cases on the basis of the given set of rules
	def validation(self,dir,protocol,port,ip,records):
		res = [0 for x in range(4)]
		for x in records:
			df = self.df_rules.iloc[[x]]
		for index, row in df.iterrows():
			# Check if all the four parameter match, if it matches, set that field to 1

			if row[0] == str(dir):
				res[0] = 1
			if row[1] == str(protocol):
				res[1] = 1
			if row[2] == str(port):
				res[2] = 1

			# Check if port in the given range
			elif '-' in row[2]:
				x = row[2].split('-')
				if int(port) in range(int(x[0]), int(x[1])):
					res[2] = 1

			if row[3] == str(ip):
				res[3] = 1

			# Check if ip in the given range
			elif '-' in row[3]:
				ip_part = ip.split('.')[2:]
				ip_num = int(''.join(map(str, ip_part)))
				parts = []
				y = row[3].split('-')
				for b in y:
					a = b.split('.')[2:]
					parts.append(int(''.join(map(str, a))))
				if ip_num in range(parts[0], parts[1]):
					res[3] = 1
			# res contains 4 values, each set to 0 or 1
			return res

	def accept(self,dir,protocol,port,ip):
		# if flag is set to false - terminate process

		if self.flag == True:
			# for valid test case, match Ip or Port number
			matchPort = self.df_rules.loc[self.df_rules[2] == str(port)]
			matchIp = self.df_rules.loc[self.df_rules[3] == str(ip)]
			records = set(matchIp.index.values).union(set(matchPort.index.values))

			# If one of the two matches with the rules, check for other parameters
			if len(records) >= 1:
				res = self.validation(dir,protocol,port,ip,records)

			else:
				# Check for matching Direction or protocol
				matchDir = self.df_rules.loc[self.df_rules[0] == str(dir)]
				matchProtocol = self.df_rules.loc[self.df_rules[1] == str(protocol)]
				records = set(matchDir.index.values).union(set(matchProtocol.index.values))

				#If one of them matches, check for other parameters
				if len(records) >= 1:
					res = self.validation(dir, protocol, port, ip, records)

			# If all the 4 values match, sum of res is 4
			if sum(res) == 4:
				return True
			else:
				# Even if one of the values don't match with the rules, it is not accepted, returns False
				return False
		else:
			return False



if __name__ == "__main__":
	# sys.argv[1] -- rules.csv file path
	firewall = Firewall(sys.argv[1])
	input = sys.argv[2] # test cases file path
	f = open(input,"r")
	for x in f:
		# pre-processing of the test cases, removing extra quotes (" "), striping white spaces
		y = firewall.preprocess(x)
		# Main method for acceptance testing
		isAccepted = firewall.accept(y[0],y[1],int(y[2]),y[3])
		# Prints the result - True/False
		print(str(isAccepted))
