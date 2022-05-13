import file_internal

class FileInfo:
	def __init__(self,path):
		self.path = path
		self.basic_info = None
		self.stat_info = None
		self.stardard_info = None

	def get_basic_info(self):
		self.basic_info = file_internal.get_basic_info(self.path)
		return self.basic_info

	def get_stat_info(self):
		self.stat_info = file_internal.get_stat_info(self.path)
		return self.stat_info

	def get_standard_info(self):
		self.stardard_info = file_internal.get_stardard_info(self.path)
		return self.stardard_info
		