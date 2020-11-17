from urllib.parse import urlparse
from string import Template
from msiempy import NitroSession
from msiempy import NitroList as List

"""
This script lists all possible arguments we can use with NitroSession.request()
"""

session = NitroSession()

def get_list_of_request_params():
    all_params=[]
    for k, v in session.PARAMS.items():
        name = "{}".format(k)
        params = []
        endpoint = "{}".format(
            urlparse(v[0] if not isinstance(v[0], Template) else v[0].template).path
        )
        if isinstance(v[0], Template):
            params += [
                s[1] or s[2]
                for s in Template.pattern.findall(v[0].template)
                if s[1] or s[2]
            ]
        if isinstance(v[1], Template):
            params += [
                s[1] or s[2]
                for s in Template.pattern.findall(v[1].template)
                if s[1] or s[2]
            ]

        all_params.append({'Request':name, 'Arguments':params, 'Endpoint':endpoint})
    
    return all_params

if __name__ == "__main__":
    param = List(get_list_of_request_params())
    string = ""
    for p in param:
        string+='>>> s.request("{method}", {args}) # Call {endpoint}\n'.format(
            method=p['Request'],
            args=', '.join(p['Arguments']) if p['Arguments'] else '',
            endpoint=p['Endpoint']
        )
    print(string)
