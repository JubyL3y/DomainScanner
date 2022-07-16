from typing import Dict, Optional, List
from functools import reduce
import json
import logging
import requests


class DNSTrailsScannerException(Exception):
    pass

class DNSTrailsScanner:
    __base_url = "https://api.securitytrails.com/v1/"


    def __init__(self, api_key: str):
        self.__headers = {
            "APIKEY":api_key,
            "Content-Type": "pplication/json"
        }
        self.__logger = logging.getLogger(f"DNSTrailsScanner-{api_key}")
        res = self.ping()
        if "success" not in res.keys():
            raise DNSTrailsScannerException(res["message"])
    

    def __request(self, api_method:str, path_param: Optional[str] = None, method_suffix: Optional[str]=None, params: Optional[Dict] = None):
        method_url = self.__base_url+api_method
        if path_param:
            method_url += "/"+path_param
        if method_suffix:
            method_url += "/"+method_suffix
        if params:
            if len(params.items()) == 1:
                param = list(params.items())[0]
                params_str = f"{param[0]}={param[1]}"
            else:
                params_str = reduce((lambda x,y: f"{x[0]}={x[1]}&{y[0]}={y[1]}" if type(x) is tuple else  x+f"&{y[0]}={y[1]}"),params.items())
            method_url+="?"+params_str
        self.__logger.debug(f"Send request: {method_url}")
        return json.loads(requests.get(method_url, headers=self.__headers).content)

    def description(self):
        return f"DNSTrails Scanner. API Key: {self.__headers['APIKEY']}"

    def ping(self):
        return self.__request("ping")
    
    def usage(self):
        return self.__request("account", method_suffix = "usage")

    def get_qouta(self) -> int:
        data = self.usage()
        return data["allowed_monthly_usage"]-data["current_monthly_usage"]
        

    def get_subdomains(self, domain:str) -> List[str]:
        result = self.__request("domain", path_param=domain, method_suffix="subdomains")
        if "subdomains" not in result.keys():
            raise DNSTrailsScannerException("No have result, check quota")
        return list(map(lambda x: x+"."+domain, result["subdomains"]))
