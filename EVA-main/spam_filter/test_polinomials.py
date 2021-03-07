# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

from eva import EvaProgram, Input, Output, evaluate, save, load
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse
import numpy as np

#################################################
def polinomal_function(a,b,c, vector_size):
    print('Compile time')
    # print("The function: y = 3x^2 + 5x - 2")
    poly = EvaProgram('Polynomial', vec_size=vector_size)
    # a = 10
    # b = 40
    # c = 5
    print("The polinomial function: y = {}x^2 + {}x - {}; vector_size = {}".format(a,b,c, vector_size))
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
        'x': [i for i in range(signature.vec_size)]
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

if __name__ == '__main__':
    polinomal_function(10,40,5, 8)
