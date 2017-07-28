
import sys

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

if len(sys.argv) != 2 and len(sys.argv) != 3:
	print("\nUsage:\nFunctionToHash.py [Module] [Function]\nFunctionToHash.py kernel32.dll CreateProcessA\n\nOR\n\nFunctionToHash.py [Function]\nFunctionToHash.py ExportedFunction")
	exit()

if len(sys.argv) == 3:
	module = sys.argv[1].upper().encode('UTF-16LE') + b'\x00\x00'
	function = sys.argv[2].encode() + b'\x00'

	functionHash = 0

	for b in function:
		functionHash = ror(functionHash, 13, 32)
		functionHash += b

	moduleHash = 0

	for b in module:
		moduleHash = ror(moduleHash, 13, 32)
		moduleHash += b

	functionHash += moduleHash

	if functionHash > 0xFFFFFFFF: functionHash -= 0x100000000

else:
	function = sys.argv[1].encode() + b'\x00'

	functionHash = 0

	for b in function:
		functionHash = ror(functionHash, 13, 32)
		functionHash += b


print(hex(functionHash))
