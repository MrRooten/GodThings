def meta_data():
    res = dict()
    res["Description"] = "Python List Process"
    res["Name"] = "PyListProcess2"
    res["Type"] = "Python"
    res["Class"] = "GetInfo"
    return res
import process_internal
def module_run(args):
    print("Start module1...")
    print("End module1...")
    pid_list = process_internal.get_pids()
    pids = []
    process_names = []
    process_usernames = []
    for i in pid_list:
        pids.append(str(i))
        process_names.append(process_internal.get_process_name(i))
        process_usernames.append(process_internal.get_process_username(i))
    return {"pid":pids,"process_name":process_names,"username":process_usernames}

