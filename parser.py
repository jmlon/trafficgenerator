import logging

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("scene_parser")
logger.setLevel(logging.INFO)

scenario = { 'flows': [] }


def parse_scenario(filename):
    with open(filename, 'rt') as fh:
        for line in fh:
            tokens = line.strip().split()
            # print(tokens)
            if len(tokens)>0 and not tokens[0].startswith('#'):
                first = tokens.pop(0)
                # print(f'||{l}||')
                if first.startswith("type:"):
                    set_type(tokens)
                elif first.startswith("repeat:"):
                    set_repeat(tokens)
                elif first.startswith("on:"):
                    set_on(tokens)
                elif first.startswith("off:"):
                    set_off(tokens)
                elif first.startswith("end"):
                    set_end(tokens)
    return scenario

def set_type(t):
    scenario['type'] = t.pop(0)

def set_repeat(t):
    scenario['repeat'] = int(t.pop(0))

def set_off(t):
    if t.pop(0).startswith('time:'):
        offtime = float(t.pop(0))
    scenario['flows'].append({ 'on': False, 'offtime':offtime })

def set_end(t):
    pass

def set_on(t):
    quantity = on_quantity(t)
    interval = on_interval(t)
    size     = on_size(t)
    destination = on_destination(t)
    flow = { 'on':True, 'quantity':quantity, 'interval':interval, 'size':size, 'dest':destination }
    scenario['flows'].append(flow)

def on_quantity(t):
    token = t.pop(0)
    qty = {} # { 'mode':None, 'secs':None, 'packets':None }
    if token=="time:":
        qty['mode']='time'
        qty['secs']=float(t.pop(0))
    elif token=="packet:":
        qty['mode']='packet'
        qty['packets']=int(t.pop(0))
    else:
        logger.error('Invalid quantity')
    logger.debug(qty)
    return qty

def on_interval(t):
    token = t.pop(0)
    interval = {}
    if token=='greedy':
        interval['mode']='greedy'
    elif token=='const':
        interval['mode']='const'
        interval['time']=float(t.pop(0))
    elif token=='uniform':
        interval['mode']='uniform'
        interval['min'] = float(t.pop(0))
        interval['max'] = float(t.pop(0))
    elif token=='exponential':
        interval['mode']= 'exponential'
        interval['mean']= float(t.pop(0))
        interval['min'] = float(t.pop(0))
        interval['max'] = float(t.pop(0))
    else:
        logger.error('Invalid interval')
    logger.debug(interval)
    return interval

def on_size(t):
    token = t.pop(0)
    assert(token=='length:')
    token = t.pop(0)
    size = {}
    if token=='const':
        size['mode']='const'
        size['packet_size']=int(t.pop(0))
    elif token=='uniform':
        size['mode']='uniform'
        size['min'] = int(t.pop(0))
        size['max'] = int(t.pop(0))
    elif token=='exponential':
        size['mode']= 'exponential'
        size['mean']= float(t.pop(0))
        size['min'] = int(t.pop(0))
        size['max'] = int(t.pop(0))
    else:
        logger.error('Invalid size')
    logger.debug(size)
    return size

def on_destination(t):
    token = t.pop(0)
    dst = {}
    if token=='dest:':
        dst['addr']=t.pop(0)
        dst['port']=int(t.pop(0))
        dst['mac']=t.pop(0)
    else:
        logger.error('Invalid destination')
    return dst


if __name__ == "__main__":
    parse_scenario('flow-10.0.0.2') #('sample_scenery')
    print(scenario)

