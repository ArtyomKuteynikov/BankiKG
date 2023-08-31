import requests
import datetime

ADDRESS = "http://127.0.0.1:5000/api"
DEFAULT_PARAMS = {
    'token': "5zqxZa16b0vEE1sx$9a74b2452862f8b0061a5356079f69c3b83af9aec7430d070901f745b984a3f9",
    'OS': "Android",
    'DeviceID': "Gnx786nzdg758"
}
DEFAULT_DATA = None
mapping = {"<class 'str'>": 'string', "<class 'int'>": 'integer', "<class 'float'>": 'number', "<class 'bool'>": 'boolean'}
def auto_doc(endpoint, params=DEFAULT_PARAMS, data=DEFAULT_DATA, req_type='get', desciption='Тестовый эндпоинт', tag="map"):
    result = f'''
   ---
   {req_type}:
     summary: {desciption}
     parameters:'''
    for i in params:
        result += f'''
         - in: query
           name: {i}
           schema:
             type: {mapping[str(type(params[i]))]}
             example: {params[i]}
           description: {i}'''
    if data:
        example = ''
        result += '''
     requestBody:
        content:
          application/json:
              schema:
                type: object
                properties:
        '''

        res = requests.post(f'{ADDRESS}{endpoint}', params=params, json = data).json()
        print(res)
        for i in data:
            print(type(data[i])==dict)
            if type(data[i]) == list:
                result += f'''
                   {i}:
                     type: array
                     items:
                       type: object
                       properties:'''
                for j in data[i][0]:
                    result += f'''
                           {j}:
                             type: {mapping[str(type(data[i][0][j]))]}'''
                    example += f'''{j}: res[i][0][j]'''
            elif type(data[i]) == dict:
                result += f'''
                   {i}:
                     type: object
                     properties:'''
                for j in data[i][0]:
                    if type(data[i][0][j]) == dict:
                        result += f'''
                           {j}:
                             type: object
                             properties:'''
                        for k in data[i][0][j]:
                            result += f'''
                                   {k}:
                                     type: {mapping[str(type(data[i][0][j][k]))]}'''
                    elif type(data[i][0][j]) == list:
                        result += f'''
                           {j}:
                             type: array
                             items:
                               type: object
                               properties:'''
                        for k in data[i][0][j][0]:
                            result += f'''
                                   {k}:
                                     type: {mapping[str(type(data[i][0][j][0][k]))]}'''
                    else:
                        result += f'''
                           {j}:
                             type: {mapping[str(type(data[i][0][j]))]}'''
            else:
                result += f'''
                   {i}:
                     type: {mapping[str(type(data[i]))]}'''
                example += f'''
                  {i}: {data[i]}'''
        result += '''
                example:   # Sample object
        '''
        result += example
        result += '''
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:'''
        for i in res:
            if type(res[i]) == list:

                if type(res[i][0]) != dict:
                    result += f'''
                           {j}:
                             type: array
                             items:
                               type: {mapping[str(type(res[i][0][j][0]))]}'''
                else:
                    result += f'''
                   {i}:
                     type: array
                     items:
                       type: object
                       properties:'''
                    for j in res[i][0]:
                        if type(res[i][0][j]) == dict:
                            result += f'''
                           {j}:
                             type: object
                             properties:'''
                            for k in res[i][0][j]:
                                result += f'''
                                   {k}:
                                     type: {mapping[str(type(res[i][0][j][k]))]}'''
                        elif type(res[i][0][j]) == list:
                            if type(res[i][0][j][0]) != dict:
                                result += f'''
                           {j}:
                             type: array
                             items:
                               type: {mapping[str(type(res[i][0][j][0]))]}'''
                            else:
                                result += f'''
                           {j}:
                             type: array
                             items:
                               type: object
                               properties:'''
                                for k in res[i][0][j][0]:
                                    result += f'''
                                   {k}:
                                     type: {mapping[str(type(res[i][0][j][0][k]))]}'''
                    else:
                        result += f'''
                           {j}:
                             type: {mapping[str(type(res[i][0][j]))]}'''
            elif type(res[i]) == dict:
                result += f'''
                   {i}:
                     type: object
                     properties:'''
                for j in res[i][0]:
                    result += f'''
                           {j}:
                             type: {mapping[str(type(res[i][0][j]))]}'''
                    example += f'''{j}: res[i][0][j]'''
            else:
                result += f'''
                   {i}:
                     type: {mapping[str(type(res[i]))]}'''
    else:
        res = requests.get(f'{ADDRESS}{endpoint}', params=params).json()
        print(res)
        result += '''
     responses:
       '200':
         description: Результат
         content:
           application/json:
             schema:      # Request body contents
               type: object
               properties:'''
        for i in res:
            print(res[i], type(res[i]) == dict, type(res[i]))
            if type(res[i]) == list:
                if type(res[i][0]) != dict:
                    result += f'''
                           {j}:
                             type: array
                             items:
                               type: {mapping[str(type(res[i][0]))]}'''
                else:
                    result += f'''
                   {i}:
                     type: array
                     items:
                       type: object
                       properties:'''
                    for j in res[i][0]:
                        if type(res[i][0][j]) == dict:
                            result += f'''
                           {j}:
                             type: object
                             properties:'''
                            for k in res[i][0][j]:
                                result += f'''
                                   {k}:
                                     type: {mapping[str(type(res[i][0][j][k]))]}'''
                        elif type(res[i][0][j]) == list:
                            if type(res[i][0][j][0]) != dict:
                                result += f'''
                           {j}:
                             type: array
                             items:
                               type: {mapping[str(type(res[i][0][j][0]))]}'''
                            else:
                                result += f'''
                           {j}:
                             type: array
                             items:
                               type: object
                               properties:'''
                                for k in res[i][0][j][0]:
                                    result += f'''
                                   {k}:
                                     type: {mapping[str(type(res[i][0][j][0][k]))]}'''
                        else:
                            result += f'''
                           {j}:
                             type: {mapping[str(type(res[i][0][j]))]}'''
            elif type(res[i]) == dict:
                result += f'''
                   {i}:
                     type: object
                     properties:'''
                for j in res[i]:
                    result += f'''
                           {j}:
                             type: {mapping[str(type(res[i][j]))]}'''
                    result += f'''{j}: res[i][0][j]'''
            else:
                result += f'''
                   {i}:
                     type: {mapping[str(type(res[i]))]}'''
    result += f'''
       '400':
         description: Не передан обязательный параметр
         content:
           application/json:
             schema: ErrorSchema
       '401':
         description: Неверный токен
         content:
           application/json:
             schema: ErrorSchema
       '403':
         description: Пользователь заблокирован
         content:
           application/json:
             schema: ErrorSchema
     tags:
       - {tag}'''

    return result