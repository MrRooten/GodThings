import process_internal


class SecurityState:
    def __init__(self):
        self.groups = None
        self.session = None
        self.impersonation_level = None
        self.groups_with_privilege = None
        self.privileges = None
        self.integrity = None


class CPUState:
    def __init__(self):
        self.create_time = None
        self.exit_time = None
        self.kernel_time = None
        self.user_time = None

        self.priority = None
        self.cycles = None
        self.recordTime = None


class MemoryState:
    def __init__(self):
        self.peak_virtual_size = None
        self.virtual_size = None
        self.page_fault_count = None
        self.peak_workingset_size = None
        self.workingset_size = None
        self.quota_peak_paged_pool_usage = None
        self.quota_paged_pool_usage = None
        self.quota_peak_nonpaged_pool_usage = None
        self.quota_nonpaged_pool_usage = None
        self.pagefile_usage = None
        self.peak_pagefile_usage = None
        self.private_usage = None
        self.private_workingset_size = None
        self.shared_commit_usage = None


class IOState:
    def __init__(self):
        self.priority = None
        self.reads = None
        self.read_transfer = None
        self.writes = None
        self.write_transfer = None
        self.other = None
        self.other_transfer = None


class Handle:
    def __init__(self):
        self.handle_type_name = None
        self.handle_name = None
        self.handle_count = None
        self.pointer_count = None
        self.granted_access = None
        self.object_type_index = None
        self.handle_attributes = None


class HandleState:
    def __init__(self):
        self.handles = None


class ImageState:
    def __init__(self):
        self.image_filename = None
        self.cmdline = None


class Process:
    def __init__(self, pid):
        self.pid = pid
        self.processName = None
        self.userName = None
        self.memory_state = MemoryState()
        self.cpu_state = CPUState()
        self.latest_cpu_state = CPUState()
        self.io_state = IOState()
        self.handle_state = HandleState()
        self.image_state = ImageState()
        self.security_state = SecurityState()

    def kill(self):
        pass

    def suspend(self):
        pass

    def resume(self):
        pass

    def read_memory(self, address, size) -> bytes:
        pass

    def write_memory(self, address, in_bytes, size) -> bool:
        pass

    def get_security_state(self):
        serialize_data = process_internal.get_process_security_state(self.pid)
        if serialize_data == None or len(serialize_data) != 4:
            return self.security_state

        self.security_state.groups = serialize_data[0]
        self.security_state.session = serialize_data[1]
        self.security_state.privileges = serialize_data[2]
        self.security_state.integrity = serialize_data[3]
        return self.security_state

    def get_memory_state(self):
        serialize_data = process_internal.get_process_memory_state(self.pid)
        if serialize_data == None or len(serialize_data) != 14:
            return self.memory_state

        self.memory_state.peak_virtual_size = serialize_data[0]
        self.memory_state.virtual_size = serialize_data[1]
        self.memory_state.page_fault_count = serialize_data[2]
        self.memory_state.peak_workingset_size = serialize_data[3]
        self.memory_state.workingset_size = serialize_data[4]
        self.memory_state.quota_peak_paged_pool_usage = serialize_data[5]
        self.memory_state.quota_paged_pool_usage = serialize_data[6]
        self.memory_state.quota_peak_nonpaged_pool_usage = serialize_data[7]
        self.memory_state.quota_nonpaged_pool_usage = serialize_data[8]
        self.memory_state.pagefile_usage = serialize_data[9]
        self.memory_state.peak_pagefile_usage = serialize_data[10]
        self.memory_state.private_usage = serialize_data[11]
        self.memory_state.private_workingset_size = serialize_data[12]
        self.memory_state.shared_commit_usage = serialize_data[13]
        return self.memory_state

    def get_io_state(self):
        serialize_data = process_internal.get_process_io_state(self.pid)
        if serialize_data == None or len(serialize_data) != 7 :
            return self.io_state
        self.io_state.priority = serialize_data[0]
        self.io_state.reads = serialize_data[1]
        self.io_state.writes = serialize_data[2]
        self.io_state.other = serialize_data[3]
        self.io_state.read_transfer = serialize_data[4]
        self.io_state.write_transfer = serialize_data[5]
        self.io_state.other_transfer = serialize_data[6]
        return self.io_state

    def get_name(self):
        return process_internal.get_process_name(self.pid)

    def get_cpu_state(self):
        serialize_data = process_internal.get_process_cpu_state(self.pid)
        if serialize_data == None or len(serialize_data) != 9:
            return self.cpu_state

        self.cpu_state.create_time = serialize_data[0] + serialize_data[1] << 32
        self.cpu_state.exit_time = serialize_data[2] + serialize_data[3] << 32
        self.cpu_state.kernel_time = serialize_data[4] + serialize_data[5] << 32
        self.cpu_state.user_time = serialize_data[6] + serialize_data[7] << 32
        self.cpu_state.priority = serialize_data[8]
        return self.cpu_state

    def get_handle_state(self):
        serialize_data = process_internal.get_process_handle_state(self.pid)
        
        if serialize_data == None or len(serialize_data) != 1:
            return self.handle_state
        _handles = serialize_data[0]
        handles = []
        for _handle in _handles:
            handle = Handle()
            handle.handle_type_name = _handle[0]
            handle.handle_name = _handle[1]
            handle.handle_count = _handle[2]
            handle.pointer_count = _handle[3]
            handle.granted_access = _handle[4]
            handles.append(handle)
        self.handle_state.handles = handles
        return self.handle_state


class ProcessManager:
    def __init__(self):
        self.pids = None

    def update(self):
        pass

    def get_pids(self) -> list:
        self.pids = process_internal.get_pids()
        return self.pids
