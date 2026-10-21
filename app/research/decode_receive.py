"""Bounded AddMsg decoder, based on pinned Ipad860 mm.pb.go reference.

Field map is a reference until a real target-client receive sample validates it.
Never parse commands by assuming their command ID alone identifies a message.
"""
class DecodeError(ValueError):
    pass

def varint(data,offset):
    value=0
    for shift in range(0,70,7):
        if offset>=len(data):raise DecodeError('Truncated varint')
        byte=data[offset];offset+=1
        if shift==63 and byte>1:raise DecodeError('Varint overflow')
        value|=(byte&127)<<shift
        if byte<128:return value,offset
    raise DecodeError('Invalid varint')

def fields(data):
    if not isinstance(data,bytes) or len(data)>16384:raise DecodeError('Payload limit')
    result={};offset=0;count=0
    while offset<len(data):
        count+=1
        if count>256:raise DecodeError('Too many fields')
        tag,offset=varint(data,offset);number,wire=tag>>3,tag&7
        if not 1<=number<2**29:raise DecodeError('Invalid field number')
        if wire==0:value,offset=varint(data,offset)
        elif wire==2:
            size,offset=varint(data,offset)
            if size>len(data)-offset:raise DecodeError('Truncated bytes')
            value=data[offset:offset+size];offset+=size
        elif wire in (1,5):
            size=8 if wire==1 else 4
            if len(data)-offset<size:raise DecodeError('Truncated fixed field')
            value=data[offset:offset+size];offset+=size
        else:raise DecodeError('Unsupported wire type')
        result.setdefault(number,[]).append((wire,value))
    return result

def one(record,number,wire,required=True):
    values=record.get(number,[])
    if not values and not required:return None
    if len(values)!=1 or values[0][0]!=wire:raise DecodeError(f'Invalid field {number}')
    return values[0][1]

def builtin_string(record,number):
    nested=fields(one(record,number,2))
    try:return one(nested,1,2).decode('utf-8',errors='strict')
    except UnicodeDecodeError as exc:raise DecodeError('Invalid text encoding') from exc

def decode_add_message(payload,target_room,marker=None):
    record=fields(payload)
    from_user=builtin_string(record,2);to_user=builtin_string(record,3)
    content=builtin_string(record,5);kind=one(record,4,0)
    if from_user!=target_room:raise DecodeError('Not an incoming target-room message')
    if not to_user or to_user.endswith('@chatroom'):raise DecodeError('Invalid receiver')
    if kind!=1:raise DecodeError('Not a text message')
    if ':\n' not in content:raise DecodeError('Missing group sender prefix')
    sender,text=content.split(':\n',1)
    if not sender or len(sender)>128 or '\n' in sender or not text:raise DecodeError('Invalid sender or text')
    if marker is not None and text!=marker:raise DecodeError('Test text mismatch')
    created=one(record,9,0)
    new_id=one(record,12,0,False);old_id=one(record,1,0,False)
    if not new_id and not old_id:raise DecodeError('Missing message identity')
    return {'room_id':from_user,'receiver_id':to_user,'sender_id':sender,'content':text,
            'id':str(new_id or old_id),'created':created,'type':'text',
            'msg_source':one(record,10,2,False).decode('utf-8','strict') if 10 in record else ''}
