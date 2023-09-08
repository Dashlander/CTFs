import random

output = "HackRushCTF{1_siNcEr31Y_h0pE_you_d1DN7_So1ve_th1S_m4nu4llY_if_yes_p13aSe_13Arn_a8Out_5At_SO1VeR5_985483489Y349Y8T89T4}"

equations = []
num_left = [i for i in range(12, len(output) - 1)]

num_found = []

operations = ["+", "*", "/"]

while len(num_left) != 0:
    if len(num_left) < 4:
        num_operands = len(num_left)
    else:
        num_operands = random.randint(2, 3)
    if num_operands == 2:
        operation = random.choice(operations)
        op1 = random.choice(num_left)
        num_left.remove(op1)
        op2 = random.choice(num_left)
        num_left.remove(op2)
        if operation == "+":
            eq1 = "flag[{}] + flag[{}] == {}".format(
                op1, op2,
                ord(output[op1]) + ord(output[op2]))
            eq2 = "flag[{}] - flag[{}] == {}".format(
                op2, op1,
                ord(output[op2]) - ord(output[op1]))
            equations.extend([eq1, eq2])
        elif operation == "*":
            eq1 = "flag[{}] * flag[{}] == {}".format(
                op1, op2,
                ord(output[op1]) * ord(output[op2]))
            eq2 = "flag[{}] == {}".format(op1, ord(output[op1]))
            equations.extend([eq1, eq2])
        else:
            div_num = random.randint(10, 50)
            eq1 = "flag[{}] / {} == {}".format(op1, div_num,
                                               ord(output[op1]) // div_num)
            eq2 = "flag[{}] % {} == {}".format(op1, div_num,
                                               ord(output[op1]) % div_num)
            eq3 = "flag[{}] * flag[{}] == {}".format(
                op1, op2,
                ord(output[op1]) * ord(output[op2]))
            equations.extend([eq1, eq2, eq3])
        num_found.extend([op1, op2])
    elif num_operands == 1:
        op1 = random.choice(num_left)
        num_left.remove(op1)
        div_num = random.randint(10, 50)
        eq1 = "flag[{}] / {} == {}".format(op1, div_num,
                                           ord(output[op1]) // div_num)
        eq2 = "flag[{}] % {} == {}".format(op1, div_num,
                                           ord(output[op1]) % div_num)
        equations.extend([eq1, eq2])
    elif num_operands == 3:
        op1 = random.choice(num_left)
        num_left.remove(op1)
        op2 = random.choice(num_left)
        num_left.remove(op2)
        op3 = random.choice(num_left)
        num_left.remove(op3)
        eq1 = "flag[{}] + flag[{}] == flag[{}] + {}".format(
            op1, op2, op3,
            ord(output[op1]) + ord(output[op2]) - ord(output[op3]))
        eq2 = "flag[{}] - flag[{}] + flag[{}] == {}".format(
            op1, op2, op3,
            ord(output[op1]) - ord(output[op2]) + ord(output[op3]))
        eq3 = "flag[{}] + flag[{}] == {} - flag[{}]".format(
            op2, op1,
            ord(output[op2]) + ord(output[op1]) + ord(output[op3]), op3)
        equations.extend([eq1, eq2, eq3])
        num_found.extend([op1, op2, op3])

# print(equations)
big_eq = "if(!("
# for eq in equations:
#     # not_eq = eq.replace("=", "!", 1)
#     # print(f'''if({not_eq}) {{\n\treturn 0;\n}}''')
#     big_eq += "(" + eq + ")" + " && "
big_eq += " && ".join(["(" + i + ")" for i in equations])
big_eq += ")){\nreturn 0;\n}"
print(big_eq)
