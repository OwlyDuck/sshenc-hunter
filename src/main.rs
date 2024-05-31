use std::{collections::{HashMap, LinkedList}, env, fs};
use regex::Regex;
use std::ffi::CStr;

struct SSHencData<'a> {
	task_name: String,
	sshenc_addr: u64,
	cipher_name: String,
	key: &'a[u8],
	iv: &'a[u8],
}

fn format_byte_array(byte_array: &[u8]) -> String {
	{
		let mut hex_view = String::new();
		for byte in byte_array.iter() {
			hex_view.push_str(&format!("{byte:02x}"))
		}
		hex_view
	}
}

fn create_hashmap() -> HashMap<String, (u32, u32)> {
	{
		let mut protocols = HashMap::new();
		protocols.insert("chacha20-poly1305@openssh.com".to_string(), (8, 64));
		protocols.insert("des".to_string(), (8, 8));
		protocols.insert("3des".to_string(), (8,16));
		protocols.insert("blowfish".to_string(), (8, 32));
		protocols.insert("blowfish-cbc".to_string(), (8, 16));
		protocols.insert("cast128-cbc".to_string(), (8, 16));
		protocols.insert("arcfour".to_string(), (8, 16));
		protocols.insert("arcfour128".to_string(), (8, 16));
		protocols.insert("arcfour256".to_string(), (8, 32));
		protocols.insert("acss@openssh.org".to_string(), (16, 5));
		protocols.insert("3des-cbc".to_string(), (8, 24));
		protocols.insert("aes128-cbc".to_string(), (16, 16));
		protocols.insert("aes192-cbc".to_string(), (16, 24));
		protocols.insert("aes256-cbc".to_string(), (16, 32));
		protocols.insert("rijndael-cbc@lysator.liu.se".to_string(), (16, 32));
		protocols.insert("aes128-ctr".to_string(), (16, 16));
		protocols.insert("aes192-ctr".to_string(), (16, 24));
		protocols.insert("aes256-ctr".to_string(), (16, 32));
		protocols.insert("aes128-gcm@openssh.com".to_string(), (16, 16));
		protocols.insert("aes256-gcm@openssh.com".to_string(), (16, 32));

		protocols
	}
}

fn get_pointing_to(address: u64, heap_range: (u64, u64), heap_data: &Vec<u8>) -> u64 {
	let offset = (address - heap_range.0) as usize;
	u64::from_le_bytes(heap_data[offset..offset+8].try_into().unwrap())
}

fn parse_filename(filename: &String) -> (u64, u64) {
	let re = Regex::new(r"pid\.[0-9]+\.[a-z]+\.0x([0-9a-f]+)-0x([0-9a-f]+)\.dmp").expect("Could not create regex"); 
	let caps = re.captures(&filename).unwrap();

	if caps.len() != 3 {
		panic!("could not parse string");
	}
	(u64::from_str_radix(&caps[1], 16).unwrap(), u64::from_str_radix(&caps[2], 16).unwrap())
}

fn is_in_range(address: u64, heap_range: (u64, u64)) -> bool {
	(heap_range.0 <= address) && (address <= heap_range.1 - 8)
}

fn get_pointer_addresses(heap_range: (u64, u64), heap_data: &Vec<u8>) -> LinkedList<u64> {
	let mut valid_pointer_addresses: LinkedList<u64> = LinkedList::new();
	for offset in 0..heap_data.len()-8 {
		let pointed_to = u64::from_le_bytes(heap_data[offset..offset+8].try_into().unwrap());
		if is_in_range(pointed_to, heap_range) {
			valid_pointer_addresses.push_back(heap_range.0 + (offset as u64));
		}
	}
	valid_pointer_addresses
}

fn get_cstring(address: u64, heap_range: (u64, u64), heap_data: &Vec<u8>) -> &CStr {
	let offset = (address - heap_range.0) as usize;
	CStr::from_bytes_until_nul(&heap_data[offset..]).unwrap()
}

fn get_string(address: u64, heap_range: (u64, u64), heap_data: &Vec<u8>) -> Result<String, std::str::Utf8Error> {
	let string = get_cstring(address, heap_range, heap_data).to_str()?;
	Ok(string.to_owned())
}

fn is_valid_protocol(candidate: &String, protocols: &HashMap<String, (u32, u32)>) -> bool {
	protocols.contains_key(candidate)
}

fn get_protocol(pointer: u64, heap_range: (u64, u64), heap_data: &Vec<u8>, protocols: &HashMap<String, (u32, u32)>) -> Option<String> {
	let pointed_to = get_pointing_to(pointer, heap_range, &heap_data);
	let candidate = get_string(pointed_to, heap_range, &heap_data);
	match candidate {
		Ok(protocol) => if is_valid_protocol(&protocol, &protocols) {Some(protocol)} else {None},
		Err(_) => None
	}
}

fn get_values<'a>(address: u64, heap_range: (u64, u64), heap_data: &'a Vec<u8>, protocol_values: &(u32, u32)) -> Option<(&'a[u8], &'a[u8])> {
	let offset = (address - heap_range.0) as usize;
	if !is_in_range(address+8, heap_range) {
		return None;
	}

	let key_len_offset = offset + 20;
	let key_len = u32::from_le_bytes(heap_data[key_len_offset..key_len_offset+4].try_into().unwrap());
	
	if key_len != protocol_values.1 {
		return None;
	}

	let block_size_offset = offset + 28;
	let block_size = u32::from_le_bytes(heap_data[block_size_offset..block_size_offset+4].try_into().unwrap());

	if block_size != protocol_values.0 {
		return None;
	}

	let key_offset = offset + 32;
	let key_pointer = u64::from_le_bytes(heap_data[key_offset..key_offset+8].try_into().unwrap());

	if !is_in_range(key_pointer, heap_range) {
		return None;
	}

	let key_index = (key_pointer - heap_range.0) as usize;

	let iv_offet = offset + 40;
	let iv_pointer = u64::from_le_bytes(heap_data[iv_offet..iv_offet+8].try_into().unwrap());

	if !is_in_range(iv_pointer, heap_range) {
		return None;
	}
	let iv_index = (iv_pointer - heap_range.0) as usize;

	let iv_len_offset = offset + 24;
	let iv_len = u32::from_le_bytes(heap_data[iv_len_offset..iv_len_offset+4].try_into().unwrap());

	let key: &'a[u8] = &heap_data[key_index..key_index+(key_len as usize)];
	let iv = &heap_data[iv_index..iv_index+(iv_len as usize)];

	Some((key, iv))
}

fn get_sshenc_structs<'a>(heap_range: (u64, u64), heap_data: &'a Vec<u8>, protocols: &HashMap<String, (u32, u32)>) -> LinkedList<SSHencData<'a>> {
	let mut sshenc_datas: LinkedList<SSHencData> = LinkedList::new();

	for pointer in get_pointer_addresses(heap_range, &heap_data) {
		let protocol = get_protocol(pointer, heap_range, heap_data, protocols);
		if protocol.is_none() {
			continue;
		}
		let protocol_name = protocol.unwrap();

		println!("{:#08x}", pointer);
		let protocol_values = protocols.get(&protocol_name).unwrap();
		let values: (&[u8], &[u8]);
		match get_values(pointer, heap_range, heap_data, protocol_values) {
			Some(v) => values = v,
			None => continue
		}
		let sshenc_data = SSHencData {
			task_name: "whatever".to_string(),
			sshenc_addr: pointer,
			cipher_name: protocol_name,
			key: values.0,
			iv: values.1
		};
		sshenc_datas.push_back(sshenc_data);
	}
	sshenc_datas
}

fn main() -> Result<(), std::io::Error> {
	let args: Vec<_> = env::args().collect();
	if args.len() < 2 {
		panic!("Usage : {} <file>", args[0]);
	}

	let heap_range: (u64, u64) = parse_filename(&args[1]);
	println!("heap range: {:#08x}-{:#08x}", heap_range.0, heap_range.1);

	let heap_data = fs::read(&args[1])?;
	if (heap_data.len() as u64) != (heap_range.1 - heap_range.0) {
		panic!("wrong data len");
	}

	let protocols = create_hashmap();

	let found_structs: LinkedList<SSHencData> = get_sshenc_structs(heap_range, &heap_data, &protocols);

	for sshenc_struct in found_structs.iter() {
		println!("{{\"task_name\":\"{}\", \"sshenc_addr\": {}, \"cipher_name\": \"{}\", \"iv\": \"{}\", \"key\": \"{}\"}}", sshenc_struct.task_name, sshenc_struct.sshenc_addr, sshenc_struct.cipher_name, format_byte_array(sshenc_struct.iv), format_byte_array(sshenc_struct.key))
	}
	Ok(())
}
