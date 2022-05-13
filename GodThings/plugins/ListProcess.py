def meta_data():
    res = dict()
    res["Description"] = "Python List Process"
    res["Name"] = "PyListProcess"
    res["Type"] = "Python"
    res["Class"] = "GetInfo"
    return res
import process_internal
def module_run(args):
    print("Start module1...")
    print("End module1...")
    a = process_internal.get_pids()
    b = []
    for i in a:
        b.append(str(i))
    print(b)
    return {"result":b}

