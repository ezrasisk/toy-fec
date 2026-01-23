use std::collections::{HashMap, HashSet};
use rand::seq::SliceRandom;
use rand::thread_rng;
use hex::encode;
use raptorq::{Decoder, Encoder, EncodingPacket};
use sha2::{Digest, Sha256};

const K: usize = 15;                    // GHOSTDAG k-parameter
const STITCH_THRESHOLD: usize = 10;     // When StitchBot merges tips
const SYMBOL_SIZE: u16 = 128;           // Good size for ~32-byte hashes/headers
const REPAIR_PACKETS: u32 = 50;         // Extra repair packets (very robust)
const SIMULATED_LOSS: usize = 30;       // Test with significant loss

//Losses tested secure upto parity 

#[derive(Debug, Clone)]
struct Block {
    id: u64,
    parents: Vec<u64>,
    color: Color,
    hash: [u8; 32],                     // SHA256 hash of (id + sorted parent IDs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Color {
    Blue,
    Red,
}

struct ToyDag {
    blocks: HashMap<u64, Block>,
    tips: HashSet<u64>,
    next_id: u64,
    selected_parent: u64,
}

impl ToyDag {
    fn new() -> Self {
        let genesis_hash: [u8; 32] = [0; 32];
        let genesis = Block {
            id: 0,
            parents: vec![],
            color: Color::Blue,
            hash: genesis_hash,
        };
        let mut blocks = HashMap::new();
        blocks.insert(0, genesis);

        ToyDag {
            blocks,
            tips: HashSet::from([0]),
            next_id: 1,
            selected_parent: 0,
        }
    }

    fn anticone_size(&self, block_id: u64, reference_id: u64) -> usize {
        let reachable_from_block = self.future_set(block_id);
        let reachable_from_ref = self.future_set(reference_id);
        reachable_from_block.difference(&reachable_from_ref).count().saturating_sub(1)
    }

    fn future_set(&self, block_id: u64) -> HashSet<u64> {
        let mut future = HashSet::new();
        let mut queue = vec![block_id];
        future.insert(block_id);

        while let Some(current) = queue.pop() {
            for (&child_id, child) in &self.blocks {
                if child.parents.contains(&current) && future.insert(child_id) {
                    queue.push(child_id);
                }
            }
        }
        future
    }

    fn past_set(&self, block_id: u64) -> HashSet<u64> {
        let mut past = HashSet::new();
        let mut queue = vec![block_id];
        past.insert(block_id);

        while let Some(current) = queue.pop() {
            for &parent in &self.blocks[&current].parents {
                if past.insert(parent) {
                    queue.push(parent);
                }
            }
        }
        past
    }

    fn create_block(&mut self, parent_ids: Vec<u64>) -> u64 {
        assert!(!parent_ids.is_empty());

        let id = self.next_id;
        self.next_id += 1;

        // Color (note: in this simplified toy, new blocks are always Blue because they're not yet in the DAG)
        let color = if self.anticone_size(id, self.selected_parent) <= K {
            Color::Blue
        } else {
            Color::Red
        };

        // Compute deterministic SHA256 hash from id + sorted parent IDs
        let mut sorted_parents = parent_ids.clone();
        sorted_parents.sort();
        let mut hasher = Sha256::new();
        hasher.update(&id.to_be_bytes());
        for &p in &sorted_parents {
            hasher.update(&p.to_be_bytes());
        }
        let hash: [u8; 32] = hasher.finalize().into();

        let block = Block {
            id,
            parents: parent_ids.clone(),
            color,
            hash,
        };

        self.blocks.insert(id, block);

        // Update tips
        for &pid in &parent_ids {
            if self.tips.len() > 1 || !self.tips.contains(&pid) {
                self.tips.remove(&pid);
            }
        }
        self.tips.insert(id);

        // Update selected parent (heaviest blue tip)
        self.update_selected_parent();

        id
    }

    fn update_selected_parent(&mut self) {
        let blue_tips: Vec<u64> = self
            .tips
            .iter()
            .filter(|&&t| self.blocks[&t].color == Color::Blue)
            .copied()
            .collect();

        if let Some(&best) = blue_tips
            .iter()
            .max_by_key(|&&t| self.past_set(t).len())
        {
            self.selected_parent = best;
        }
    }

    fn stitch_if_needed(&mut self) {
        if self.tips.len() > STITCH_THRESHOLD {
            println!(" StitchBot ACTIVATED! Tips: {} → merging all!", self.tips.len());

            let all_tips: Vec<u64> = self.tips.iter().copied().collect();
            self.create_block(all_tips.clone());

            println!(" Created merge block referencing {} tips", all_tips.len());
        }
    }

    fn print_dag(&self) {
        println!("=== DAG State ===");
        println!(
            "Blocks: {} | Tips: {} | Selected Parent: {} ({:?})",
            self.blocks.len(),
            self.tips.len(),
            self.selected_parent,
            self.blocks[&self.selected_parent].color
        );

        let mut sorted: Vec<_> = self.blocks.values().collect();
        sorted.sort_by_key(|b| b.id);

        for block in sorted {
            let color_char = match block.color {
                Color::Blue => "BLUE",
                Color::Red => "RED",
            };
            println!(
                "{} Block {} | Parents: {:?} | Past size: {} | Hash: {}",
                color_char,
                block.id,
                block.parents,
                self.past_set(block.id).len(),
                encode(block.hash)
            );
        }
        println!("=================\n");
    }
}

fn main() {
    let mut dag = ToyDag::new();
    let mut rng = thread_rng();

    println!("Starting high-throughput DAG simulation with k={} and StitchBot...\n", K);

    for i in 1..=150 {  // 150 new blocks → 151 total
        let current_tips: Vec<u64> = dag.tips.iter().copied().collect();
        let num_parents = current_tips.len().min(3);

        let parents: Vec<u64> = current_tips
            .choose_multiple(&mut rng, num_parents)
            .copied()
            .collect();

        dag.create_block(parents);

        if i % 5 == 0 {
            dag.stitch_if_needed();
        }

        if i % 30 == 0 {
            dag.print_dag();
        }
    }

    println!("Final state: {} blocks, {} tips, selected parent {}\n",
        dag.blocks.len(), dag.tips.len(), dag.selected_parent);

    // ====================== FEC on all block hashes ======================
    println!("=== RaptorQ FEC on all block hashes ===\n");

    let mut sorted_blocks: Vec<_> = dag.blocks.values().collect();
    sorted_blocks.sort_by_key(|b| b.id);

    let mut data_bytes = Vec::new();
    for (idx, block) in sorted_blocks.iter().enumerate() {
        println!("Block {:3} (id {:3}) hash: {}", idx, block.id, encode(block.hash));
        data_bytes.extend_from_slice(&block.hash);
    }

    let data_len = data_bytes.len();
    println!("\nTotal data: {} bytes ({} blocks × 32 bytes)\n", data_len, sorted_blocks.len());

    let encoder = Encoder::with_defaults(&data_bytes, SYMBOL_SIZE);
    let packets: Vec<EncodingPacket> = encoder.get_encoded_packets(REPAIR_PACKETS);

    println!("Generated {} packets (source + {} repair)\n", packets.len(), REPAIR_PACKETS);

    // Simulate packet loss
    let mut received_packets = packets;
    received_packets.shuffle(&mut rng);
    received_packets.truncate(received_packets.len().saturating_sub(SIMULATED_LOSS));

    println!("Simulated loss: {} packets lost → {} remaining\n", SIMULATED_LOSS, received_packets.len());

    // Decode
    let config = encoder.get_config();
    let mut decoder = Decoder::new(config);
    let mut reconstructed = None;

    for packet in received_packets {
        if let Some(data) = decoder.decode(packet) {
            reconstructed = Some(data);
            println!("Reconstruction succeeded early!");
            break;
        }
    }

        match reconstructed {
        Some(recovered) => {
            println!("\nFULL RECOVERY! {} bytes reconstructed.", recovered.len());

            // Show ALL recovered hashes (no longer limited to 10)
            println!("Recovered block hashes (in creation order):\n");
            for (idx, chunk) in recovered.chunks_exact(32).enumerate() {
                println!("Recovered block {:3} hash: {}", idx, encode(chunk));
            }

            // Optional: verify perfect match with originals
            if recovered == data_bytes {
                println!("\n Perfect match! All {} recovered hashes exactly match the originals.", sorted_blocks.len());
            } else {
                println!("\n Mismatch detected — reconstruction error.");
            }
        }
        None => {
            println!("\nReconstruction failed — increase REPAIR_PACKETS or reduce loss.");
        }
    }
}
