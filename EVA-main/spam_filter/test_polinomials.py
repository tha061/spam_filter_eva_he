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

#################################################
def polynomial_function(a,b,c, vector_size):
    print('Compile time')
    # print("The function: y = 3x^2 + 5x - 2")
    poly = EvaProgram('Polynomial', vec_size=vector_size)
    # a = 10
    # b = 40
    # c = 5
    print("The polynomial function: y = {}x^2 + {}x - {}; vector_size = {}".format(a,b,c, vector_size))
    with poly:
        x = Input('x')
        Output('y', a*x**2 + b*x - c)

    poly.set_output_ranges(20)
    poly.set_input_scales(20)


    compiler = CKKSCompiler()
    poly, params, signature = compiler.compile(poly)

    save(poly, 'poly.eva')
    save(params, 'poly.evaparams')
    save(signature, 'poly.evasignature')

    #################################################
    print('Key generation time')

    params = load('poly.evaparams')

    public_ctx, secret_ctx = generate_keys(params)

    save(public_ctx, 'poly.sealpublic')
    save(secret_ctx, 'poly.sealsecret')

    #################################################
    print('Runtime on client')

    signature = load('poly.evasignature')
    public_ctx = load('poly.sealpublic')

    inputs = {
        'x': [1 for i in range(signature.vec_size)]
    }
    print("inputs = {}".format(inputs))
    encInputs = public_ctx.encrypt(inputs, signature)

    print("encInputs = {}".format(encInputs))

    save(encInputs, 'poly_inputs.sealvals')

    #################################################
    print('Runtime on server')

    poly = load('poly.eva')
    public_ctx = load('poly.sealpublic')
    encInputs = load('poly_inputs.sealvals')

    encOutputs = public_ctx.execute(poly, encInputs)
    print("encOutputs = {}".format(encOutputs))

    save(encOutputs, 'poly_outputs.sealvals')

    #################################################
    print('Back on client')

    secret_ctx = load('poly.sealsecret')
    encOutputs = load('poly_outputs.sealvals')

    print("now decrypt the results: ")
    outputs = secret_ctx.decrypt(encOutputs, signature)

    print("outputs = {}".format(outputs))

    reference = evaluate(poly, inputs)
    print("refernce compute the function poly on plaintext: ")
    print('Expected', reference)
    # print('Got', outputs)
    print('MSE', valuation_mse(outputs, reference))

    return outputs, reference

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
        Output('y', (x1*2))

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

    inputs = {
        'x1': [i for i in range(signature.vec_size)]
    }

    print("inputs = {}".format(inputs))
    encInputs = public_ctx.encrypt(inputs, signature)

    print("encInputs = {}".format(encInputs))

    save(encInputs, 'mul_vec_inputs.sealvals')
    
    # # ##### y
    # inputs_y = {
    #     'y': [2*i for i in range(signature.vec_size)]
    # }
    # print("inputs_y = {}".format(inputs_y))
    # encInputs_y = public_ctx.encrypt(inputs_y, signature)
    #
    # print("encInputs_y = {}".format(encInputs_y))
    #
    # save(encInputs_y, 'enc_vec_inputs_y.sealvals')

    #################################################
    print('Runtime on server')

    mul_vec = load('mul_vec.eva')
    public_ctx = load('mul_vec.sealpublic')
    encInputs = load('mul_vec_inputs.sealvals')
    # encInputs_y = load('mul_vec_inputs_y.sealvals')

    encOutputs = public_ctx.execute(mul_vec, encInputs)
    # public_ctx.mul(encOutputs, encInputs, encInputs_y)
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
    # polynomial_function(10, 40, 5, 1024)
    mul_encrypted_vectors(8)

