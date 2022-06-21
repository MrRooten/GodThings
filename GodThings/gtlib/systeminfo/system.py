import system_internal


class SystemBasicInfo:
    def __init__(self):
        return


class SystemInfo:
    def __init__(self):
        pass

    def get_basic_info(self):
        return system_internal.get_basic_info()

    def get_perf_info(self):
        return system_internal.get_performance_info()
