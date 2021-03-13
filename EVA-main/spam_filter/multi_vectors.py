# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

from eva import EvaProgram, Input, Output, evaluate, save, load
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse
import numpy as np
from random import uniform
import unittest
import tempfile
import os
from common import *
from eva import EvaProgram, Input, Output, save, load

def mul_encrypted_vectors(vector_size):
    print('Compile time')
    # print("The function: y = 3x^2 + 5x - 2")
    mul_vec = EvaProgram('mul_encrypt_vectors', vec_size=vector_size)
    # a = 10
    # b = 40
    # c = 5
    # print("The polynomial function: y = {}x^2 + {}x - {}; vector_size = {}".format(a,b,c, vector_size))

    # prog = EvaProgram('ReductionTree', vec_size=16384)
    with mul_vec:
        x1 = Input('x1')
        x2 = Input('x2')
        Output('y', (x1*x2))

    mul_vec.set_output_ranges(20)
    mul_vec.set_input_scales(60)

    compiler = CKKSCompiler()
    mul_vec, params, signature = compiler.compile(mul_vec)

    save(mul_vec, 'mul_vec.eva')
    save(params, 'mul_vec.evaparams')
    save(signature, 'mul_vec.evasignature')

    #################################################
    print('Key generation time')

    params = load('mul_vec.evaparams')

    public_ctx, secret_ctx = generate_keys(params)

    save(public_ctx, 'mul_vec.sealpublic')
    save(secret_ctx, 'mul_vec.sealsecret')

    #################################################
    print('Runtime on client')

    signature = load('mul_vec.evasignature')
    public_ctx = load('mul_vec.sealpublic')

    # inputs = {
    #     'x1': [i for i in range(signature.vec_size)]
    # }

    inputs = {'x1': [1,2,3,4,5,6,7,8], 'x2': [1,2,3,4,5,6,7,8]}

    print("inputs = {}".format(inputs))
    encInputs = public_ctx.encrypt(inputs, signature)

    print("encInputs = {}".format(encInputs))

    save(encInputs, 'mul_vec_inputs.sealvals')
    
   

    #################################################
    print('Runtime on server')

    mul_vec = load('mul_vec.eva')
    public_ctx = load('mul_vec.sealpublic')
    encInputs = load('mul_vec_inputs.sealvals')
    

    encOutputs = public_ctx.execute(mul_vec, encInputs)
    
    print("encOutputs = {}".format(encOutputs))

    save(encOutputs, 'mul_vec_outputs.sealvals')

    #################################################
    print('Back on client')

    secret_ctx = load('mul_vec.sealsecret')
    encOutputs = load('mul_vec_outputs.sealvals')

    print("now decrypt the results: ")
    outputs = secret_ctx.decrypt(encOutputs, signature)

    print("outputs = {}".format(outputs))

    reference = evaluate(mul_vec, inputs)
    print("reference computing the function poly on plaintext: ")
    print('Expected', reference)
    # print('Got', outputs)
    print('MSE', valuation_mse(outputs, reference))

    return outputs, reference


if __name__ == '__main__':
    mul_encrypted_vectors(8)
    

