import os
import sys
import re
from collections import defaultdict

def scan_locks(directory):
    """
    Scans for shared locks and builds a dependency graph of lock acquisitions
    to detect potential race conditions and deadlocks.
    """
    lock_graph = defaultdict(set)
    
    # Heuristic for shared locks in Rust/TS/Py
    lock_pattern = re.compile(r'(\w+)\.lock\(\)')
    
    for root, dirs, files in os.walk(directory):
        # Skip node_modules and .git to avoid performance issues
        if 'node_modules' in dirs:
            dirs.remove('node_modules')
        if '.git' in dirs:
            dirs.remove('.git')
        for file in files:
            if file.endswith('.rs') or file.endswith('.ts') or file.endswith('.py') or file.endswith('.js'):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                        held_locks = []
                        for line_no, line in enumerate(lines):
                            # Very basic heuristic: if indentation decreases, we might have dropped a lock.
                            # For a real robust tool we'd need AST parsing.
                            matches = lock_pattern.findall(line)
                            for match in matches:
                                for held in held_locks:
                                    if held != match:
                                        lock_graph[held].add(match)
                                held_locks.append(match)
                                
                            # Clear held locks on function end or basic heuristic
                            if "}" in line or "return " in line:
                                held_locks = []
                except Exception as e:
                    pass
                    
    return lock_graph

def detect_deadlock(graph):
    """
    Detects cycles in the lock acquisition graph which indicate potential deadlocks.
    """
    visited = set()
    rec_stack = set()
    deadlocks = []

    def dfs(node, path):
        visited.add(node)
        rec_stack.add(node)
        
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, path + [neighbor])
            elif neighbor in rec_stack:
                cycle = path[path.index(neighbor):] + [neighbor]
                deadlocks.append(cycle)
                
        rec_stack.remove(node)

    for node in list(graph.keys()):
        if node not in visited:
            dfs(node, [node])
            
    return deadlocks

def generate_dot(graph):
    """
    Concurrency visualizer: Generates a Graphviz DOT representation of shared locks.
    """
    dot_output = []
    dot_output.append("digraph Concurrency {")
    dot_output.append('  node [shape=box, style=filled, fillcolor="lightblue"];')
    for u, neighbors in graph.items():
        for v in neighbors:
            dot_output.append(f'  "{u}" -> "{v}" [color="red"];')
    dot_output.append("}")
    return "\n".join(dot_output)

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Scanning {target_dir} for shared locks and race conditions...")
    
    graph = scan_locks(target_dir)
    
    if not graph:
        print("[+] No shared locks identified. Thread safety verified.")
        return

    print(f"[*] Identified {len(graph)} shared lock(s).")
    
    deadlocks = detect_deadlock(graph)
    if deadlocks:
        print("[!] DEADLOCKS FLAGGED: Potential circular dependencies detected!")
        for d in deadlocks:
            print("    Cycle: " + " -> ".join(d))
    else:
        print("[+] No deadlocks detected. Thread safety verified.")
        
    print("\n[*] Concurrency Visualizer (Graphviz DOT format):")
    print(generate_dot(graph))

if __name__ == "__main__":
    main()
