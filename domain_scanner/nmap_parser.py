from dataclasses import dataclass

@dataclass
class PortInfo:
    port: int
    port_type: str
    state: str
    service: str
    info: str

class NMAPScanObject:
    def __init__(self, data: str):
        self.__raw_data = data
        self.ports = []
        self.__parse_data()
    
    def __parse_data(self):
        splitted_data = self.__raw_data.split("\n")
        port_info_pos = -1
        for i in range(len(splitted_data)):
            if splitted_data[i].find("PORT     STATE")!=-1:
                port_info_pos = i+1
                break
        if port_info_pos == -1:
            return
        cur_pos = port_info_pos
        while True:
            current_line = splitted_data[cur_pos]
            splitted = current_line.split()
            try:
                port_type = splitted[0].split("/")[1]
            except IndexError:
                break
            if port_type not in ["tcp","udp"]:
                break
            port, status, service, *info = splitted
            port_num, port_type = port.split("/")
            self.ports.append(PortInfo(
                int(port_num),
                port_type,
                status,
                service,
                " ".join(info)
            ))
            cur_pos += 1      
