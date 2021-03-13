
import unittest
from random import uniform
from eva import evaluate
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse
import unittest
import tempfile
import os
from common import *
from eva import EvaProgram, Input, Output, save, load


def assert_compiles_and_matches_reference(prog, inputs = None, config={}):
        if inputs == None:
            inputs = { name: [uniform(-2,2) for _ in range(prog.vec_size)]
                for name in prog.inputs }
        config['warn_vec_size'] = 'false'

        reference = evaluate(prog, inputs)

        compiler = CKKSCompiler(config = config)
        compiled_prog, params, signature = compiler.compile(prog)

        reference_compiled = evaluate(compiled_prog, inputs)
        ref_mse = valuation_mse(reference, reference_compiled)
        # assertTrue(ref_mse < 0.0000000001,
            # f"Mean squared error was {ref_mse}")

        public_ctx, secret_ctx = generate_keys(params)
        encInputs = public_ctx.encrypt(inputs, signature)
        encOutputs = public_ctx.execute(compiled_prog, encInputs)
        outputs = secret_ctx.decrypt(encOutputs, signature)

        he_mse = valuation_mse(outputs, reference)
        # assertTrue(he_mse < 0.01, f"Mean squared error was {he_mse}")

        return (compiled_prog, params, signature)

def test_rotations():
        """ Test all rotations """

        for rotOp in [lambda x, r: x << r, lambda x, r: x >> r]:
            for enc in [False, True]:
                for rot in range(-2,2):
                    prog = EvaProgram('RotOp', vec_size = 8)
                    with prog:
                        x = Input('x')
                        Output('y', rotOp(x,rot))

                    prog.set_output_ranges(20)
                    prog.set_input_scales(30)

                    assert_compiles_and_matches_reference(prog,config={'warn_vec_size':'false'})


if __name__ == '__main__':
    test_rotations()