import pandas as pd
import sys


class Firewall:

	def __init__(self, path):
		print("path ",path[1])
		self.df_rules = pd.read_csv(path[1], header=None)
		print(self.df_rules)

	def validation(self,dir,protocol,port,ip,records):
		res = [0 for x in range(4)]
		for x in records:
			df = self.df_rules.iloc[[x]]
		#print(df)
		for index, row in df.iterrows():
			if row[0] == str(dir):
				res[0] = 1
			if row[1] == str(protocol):
				res[1] = 1
			if row[2] == str(port):
				res[2] = 1
			elif '-' in row[2]:
				x = row[2].split('-')
				#print(x,port)
				if int(port) in range(int(x[0]), int(x[1])):
					res[2] = 1
			if row[3] == str(ip):
				res[3] = 1
			elif '-' in row[3]:
				#print("here")
				ip_part = ip.split('.')[2:]
				ip_num = int(''.join(map(str, ip_part)))
				#print(ip_num)
				parts = []
				y = row[3].split('-')
				for b in y:
					a = b.split('.')[2:]
					parts.append(int(''.join(map(str, a))))
				#print(parts)
				if ip_num in range(parts[0], parts[1]):
					res[3] = 1
			return res

	def accept(self,dir,protocol,port,ip):

		matchPort = self.df_rules.loc[self.df_rules[2] == str(port)]
		matchIp = self.df_rules.loc[self.df_rules[3] == str(ip)]
		records = set(matchIp.index.values).union(set(matchPort.index.values))
		if len(records) >= 1:
			res = self.validation(dir,protocol,port,ip,records)
			#print(res)

		else:
			matchDir = self.df_rules.loc[self.df_rules[0] == str(dir)]
			matchProtocol = self.df_rules.loc[self.df_rules[1] == str(protocol)]
			records = set(matchDir.index.values).union(set(matchProtocol.index.values))
			if len(records) >= 1:
				res = self.validation(dir, protocol, port, ip, records)
				#print(res)
		#print(res)
		if sum(res) == 4:
			return True
		else:
			return False



if __name__ == "__main__":
	f = Firewall(sys.argv)
	print(f.accept("inbound", "tcp", 80, "192.168.1.2"))
	print(f.accept("inbound", "udp", 53, "192.168.2.1"))
	print(f.accept("outbound", "tcp", 10234, "192.168.10.11"))
	print(f.accept("inbound", "tcp", 81, "192.168.1.2"))
	print(f.accept("inbound", "udp", 24, "52.12.48.92"))

