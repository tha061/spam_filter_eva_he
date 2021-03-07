# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

from eva import EvaProgram, Input, Output, evaluate, save, load, mul
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse
import numpy as np

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

def mul_encrypted_vectors(vector_size):
    print('Compile time')
    # print("The function: y = 3x^2 + 5x - 2")
    enc_vec = EvaProgram('encrypt_vector', vec_size=vector_size)
    # a = 10
    # b = 40
    # c = 5
    # print("The polynomial function: y = {}x^2 + {}x - {}; vector_size = {}".format(a,b,c, vector_size))
    with enc_vec:
        x = Input('x')
        y = Input('y')
        Output('res', x*y)

    enc_vec.set_output_ranges(20)
    enc_vec.set_input_scales(20)


    compiler = CKKSCompiler()
    enc_vec, params, signature = compiler.compile(enc_vec)

    save(enc_vec, 'enc_vec.eva')
    save(params, 'enc_vec.evaparams')
    save(signature, 'enc_vec.evasignature')

    #################################################
    print('Key generation time')

    params = load('enc_vec.evaparams')

    public_ctx, secret_ctx = generate_keys(params)

    save(public_ctx, 'enc_vec.sealpublic')
    save(secret_ctx, 'enc_vec.sealsecret')

    #################################################
    print('Runtime on client')

    signature = load('enc_vec.evasignature')
    public_ctx = load('enc_vec.sealpublic')

    inputs = {
        'x': [i for i in range(signature.vec_size)],
        'y': [2*i for i in range(signature.vec_size)]
    }
    print("inputs = {}".format(inputs))
    encInputs = public_ctx.encrypt(inputs, signature)

    print("encInputs = {}".format(encInputs))

    save(encInputs, 'enc_vec_inputs.sealvals')
    
    # ##### y
    inputs_y = {
        'y': [2*i for i in range(signature.vec_size)]
    }
    print("inputs_y = {}".format(inputs_y))
    encInputs_y = public_ctx.encrypt(inputs_y, signature)

    print("encInputs_y = {}".format(encInputs_y))

    save(encInputs_y, 'enc_vec_inputs_y.sealvals')

    #################################################
    print('Runtime on server')

    enc_vec = load('enc_vec.eva')
    public_ctx = load('enc_vec.sealpublic')
    encInputs = load('enc_vec_inputs.sealvals')
    encInputs_y = load('enc_vec_inputs_y.sealvals')

    encOutputs = public_ctx.mul(enc_vec, encInputs, encInputs_y)
    # public_ctx.mul(encOutputs, encInputs, encInputs_y)
    print("encOutputs = {}".format(encOutputs))

    save(encOutputs, 'enc_vec_outputs.sealvals')

    #################################################
    print('Back on client')

    secret_ctx = load('enc_vec.sealsecret')
    encOutputs = load('enc_vec_outputs.sealvals')

    print("now decrypt the results: ")
    outputs = secret_ctx.decrypt(encOutputs, signature)

    print("outputs = {}".format(outputs))

    reference = evaluate(enc_vec, inputs)
    print("refernce compute the function poly on plaintext: ")
    print('Expected', reference)
    # print('Got', outputs)
    print('MSE', valuation_mse(outputs, reference))

    return outputs, reference

def assert_compiles_and_matches_reference(self, prog, inputs = None, config={}):
        if inputs == None:
            inputs = { name: [uniform(-2,2) for _ in range(prog.vec_size)]
                for name in prog.inputs }
        config['warn_vec_size'] = 'false'

        print('inputs = ', inputs)
        reference = evaluate(prog, inputs)

        compiler = CKKSCompiler(config = config)
        compiled_prog, params, signature = compiler.compile(prog)

        reference_compiled = evaluate(compiled_prog, inputs)
        ref_mse = valuation_mse(reference, reference_compiled)
        self.assertTrue(ref_mse < 0.0000000001,
            f"Mean squared error was {ref_mse}")

        public_ctx, secret_ctx = generate_keys(params)
        encInputs = public_ctx.encrypt(inputs, signature)
        encOutputs = public_ctx.execute(compiled_prog, encInputs)
        outputs = secret_ctx.decrypt(encOutputs, signature)

        print('outputs = ', outputs)
        print('reference = ', reference)

        he_mse = valuation_mse(outputs, reference)
        self.assertTrue(he_mse < 0.01, f"Mean squared error was {he_mse}")

        return (compiled_prog, params, signature)

if __name__ == '__main__':
    # polynomial_function(10, 40, 5, 16)
    # mul_encrypted_vectors(8)
    assert_compiles_and_matches_reference()

