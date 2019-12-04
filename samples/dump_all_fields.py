from msiempy import NitroSession
session=NitroSession()
filters=session.request('get_possible_filters')
fields=session.request('get_possible_fields', type='EVENT', groupType='NO_GROUP')
print()
print('ALL FIELDS : {}'.format([field['name'] for field in fields]))
print()
print('ALL FIELDS YOU CAN APPLY A FILTER (MORE COMMON): {}'.format([field['name'] for field in filters]))