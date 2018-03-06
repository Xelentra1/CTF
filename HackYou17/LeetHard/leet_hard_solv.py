import itertools

# 10011111000011010000110100011111
ANSWER = 2668432671

btn_nums = [1, 2, 3, 4]

perms = list(itertools.product(btn_nums, repeat = 7))

#print ('perms =', perms)

def calc(btn_num, const_val):
    if btn_num == 1:
        return const_val
    elif btn_num == 2:
        return const_val << 1
    elif btn_num == 3:
        return (const_val << 1) + const_val
    elif btn_num == 4:
        return const_val << 2
    else:
        return -1		
		
def doCalcs(btn_nums):
    path = []
    res = 0
    i = 1
    
    for n in btn_nums:
        path.append(n)
        res = calcByState(n, i, res)        
        i += 1
		
    if res == ANSWER:
        print ('path =', path)
    return res
	
def calcByState(btn_num, state, prev_res):
    if state == 1:
        return click1(btn_num)
    elif state == 2:
        return click2(prev_res, btn_num)
    elif state == 3:
        return click3(prev_res, btn_num)
    elif state == 4:
        return click4(prev_res, btn_num)
    elif state == 5:
        return click5(prev_res, btn_num)
    elif state == 6:
        return click6(prev_res, btn_num)
    elif state == 7:
        return click7(prev_res, btn_num)

def click1(btn_num):
    return 646947 * btn_num		

def click2(prev_res, btn_num):
    const_val = prev_res + 787242
    return calc(btn_num, const_val)
	
def click3(prev_res, btn_num):
    const_val = prev_res + 385656
    return calc(btn_num, const_val)
	
def click4(prev_res, btn_num):
    const_val = prev_res + 151583
    return calc(btn_num, const_val)
	
def click5(prev_res, btn_num):
    const_val = prev_res + 101591
    return calc(btn_num, const_val)
	
def click6(prev_res, btn_num):
    const_val = prev_res + 118067
    return calc(btn_num, const_val)
	
def click7(prev_res, btn_num):
    const_val = prev_res + 701881
    return calc(btn_num, const_val)
	
for p in perms:
    doCalcs(p)























