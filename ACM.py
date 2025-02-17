class AccessControlSystem:
    def __init__(self):
        self.roles = {}  # Maps roles to permissions on objects
        self.user_roles = {}  # Maps users to roles
        self.objects = {}  # Maps objects to their integrity levels
        self.role_integrity = {}  # Maps roles to their integrity levels
        self.integrity_levels = ["Low", "Medium", "High"]

    def add_role(self, role, integrity_level):
        """Creates a role with a specific integrity level."""
        if integrity_level not in self.integrity_levels:
            print(f"Error: Invalid integrity level '{integrity_level}'.")
            return
        self.roles[role] = {}
        self.role_integrity[role] = integrity_level
        print(f"Role '{role}' created with integrity level '{integrity_level}'.")

    def assign_role(self, user, role):
        """Assigns a role to a user."""
        if role not in self.roles:
            print(f"Error: Role '{role}' does not exist.")
            return
        self.user_roles[user] = role
        print(f"User '{user}' assigned to role '{role}'.")

    def add_object(self, obj, integrity_level):
        """Registers an object with an integrity level."""
        if integrity_level not in self.integrity_levels:
            print(f"Error: Invalid integrity level '{integrity_level}'.")
            return
        self.objects[obj] = integrity_level
        for role in self.roles:
            self.roles[role][obj] = set()  # Initialize object permissions for each role
        print(f"Object '{obj}' added with integrity level '{integrity_level}'.")

    def grant_permission(self, role, obj, permission):
        """Grants a permission to a role for a specific object."""
        if role not in self.roles or obj not in self.objects:
            print(f"Error: Invalid role '{role}' or object '{obj}'.")
            return
        self.roles[role][obj].add(permission)
        print(f"Granted '{permission}' permission to role '{role}' on '{obj}'.")

    def revoke_permission(self, role, obj, permission):
        """Revokes a permission from a role for a specific object."""
        if role in self.roles and obj in self.objects and permission in self.roles[role][obj]:
            self.roles[role][obj].remove(permission)
            print(f"Revoked '{permission}' permission from role '{role}' on '{obj}'.")
        else:
            print(f"Permission '{permission}' does not exist for role '{role}' on '{obj}'.")

    def check_access(self, user, obj, permission):
        """Checks if a user has permission to access an object while enforcing Biba Model rules."""
        role = self.user_roles.get(user, None)
        if role is None:
            return f"Access Denied: User '{user}' has no assigned role."

        if obj not in self.objects:
            return f"Access Denied: Object '{obj}' does not exist."

        role_integrity = self.integrity_levels.index(self.role_integrity[role])
        obj_integrity = self.integrity_levels.index(self.objects[obj])

        # Biba: No Read Down
        if permission == "read" and role_integrity < obj_integrity:
            return f"Access Denied: '{user}' cannot read '{obj}' (No Read Down - Biba)."

        # Biba: No Write Up
        if permission == "write" and role_integrity > obj_integrity:
            return f"Access Denied: '{user}' cannot write to '{obj}' (No Write Up - Biba)."

        if permission in self.roles.get(role, {}).get(obj, set()):
            return f"Access Granted: '{user}' can '{permission}' on '{obj}'."
        else:
            return f"Access Denied: '{user}' cannot '{permission}' on '{obj}'."

    def display_roles(self):
        """Displays role-based access with integrity levels."""
        print("\nRole-Based Access Control with Integrity Levels:")
        for role, objects in self.roles.items():
            integrity = self.role_integrity[role]
            print(f"\nRole: {role} (Integrity Level: {integrity})")
            for obj, permissions in objects.items():
                obj_integrity = self.objects[obj]
                print(f"  {obj} (Integrity: {obj_integrity}): {', '.join(permissions) if permissions else 'No Permissions'}")
        print("\n")


# Example Usage with Biba Model
acm = AccessControlSystem()

# Adding roles with integrity levels
acm.add_role("Admin", "High")
acm.add_role("Manager", "Medium")
acm.add_role("Employee", "Low")

# Adding objects with integrity levels
acm.add_object("Server1", "High")
acm.add_object("Database1", "Medium")
acm.add_object("HR_Files", "Low")

# Assigning roles to users
acm.assign_role("Alice", "Admin")
acm.assign_role("Bob", "Manager")
acm.assign_role("Charlie", "Employee")

# Granting permissions
acm.grant_permission("Admin", "Server1", "read")
acm.grant_permission("Admin", "Server1", "write")
acm.grant_permission("Manager", "Database1", "read")
acm.grant_permission("Employee", "HR_Files", "read")

# Checking access with Biba enforcement
print(acm.check_access("Alice", "HR_Files", "read"))  # Denied (No Read Down)
print(acm.check_access("Bob", "Server1", "write"))  # Denied (No Write Up)
print(acm.check_access("Charlie", "HR_Files", "read"))  # Granted
print(acm.check_access("Bob", "Database1", "read"))  # Granted

# Displaying roles and permissions
acm.display_roles()
