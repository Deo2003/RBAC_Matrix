Features:
Subjects & Objects Management

Dynamic addition/removal of users (Alice, Bob, Eve)
Dynamic addition/removal of resources (File1, File2, Server1)
Permission System

Grants different access rights (read, write, execute, delete)
Revokes access dynamically
Access Enforcement

Subjects can only perform actions they have explicit permission for
Access is denied by default
Security & Flexibility

Matrix structure supports multiple objects and subjects
Can be extended to include roles, groups, hierarchy enforcement

Optimizations for Large-Scale Implementation
Use a Sparse Representation (Dictionary-Based Storage)

Instead of a full matrix (O(N*M) space complexity), we store only the granted permissions in a dictionary.
This significantly reduces memory usage for systems with many workers.
Role-Based Access Control (RBAC)

Instead of assigning permissions per user, we group workers into roles (Admin, Manager, Employee).
This makes permission updates faster and more manageable.
Use Hash Maps (Dictionaries) for Fast Lookups

Instead of looping through lists, we store subjects, objects, and permissions in Python dictionaries.
This allows O(1) lookups instead of O(N) time complexity.
Batch Operations

Instead of modifying one permission at a time, we batch grant/revoke operations.
This reduces CPU and memory overhead when handling multiple updates.
Lazy Evaluation for Permissions

We check permissions on demand instead of precomputing access rights for every worker.
