class SecurityEntity:
    """Base class for security-related entities."""
    def __init__(self, name, integrity_level):
        self.name = name
        self.integrity_level = integrity_level


class Role(SecurityEntity):
    """Represents a role with permissions."""
    def __init__(self, name, integrity_level):
        super().__init__(name, integrity_level)
        self.permissions = {}  # Object -> set of permissions

    def grant_permission(self, obj, permission):
        """Grants permission for an object."""
        if obj.name not in self.permissions:
            self.permissions[obj.name] = set()
        self.permissions[obj.name].add(permission)

    def revoke_permission(self, obj, permission):
        """Revokes permission for an object."""
        if obj.name in self.permissions and permission in self.permissions[obj.name]:
            self.permissions[obj.name].remove(permission)

    def can_access(self, obj, permission):
        """Checks if the role has the required permission for an object."""
        return obj.name in self.permissions and permission in self.permissions[obj.name]


class User(SecurityEntity):
    """Represents a user assigned to a role."""
    def __init__(self, name, role):
        super().__init__(name, role.integrity_level)
        self.role = role

    def has_permission(self, obj, permission):
        """Enforces Biba Model rules before checking access."""
        if permission == "read" and self.integrity_level < obj.integrity_level:
            return False  # No Read Down
        if permission == "write" and self.integrity_level > obj.integrity_level:
            return False  # No Write Up
        return self.role.can_access(obj, permission)


class Object(SecurityEntity):
    """Represents an object/resource in the system."""
    def __init__(self, name, integrity_level):
        super().__init__(name, integrity_level)


class AccessControlSystem:
    """Manages roles, users, objects, and permissions."""
    def __init__(self):
        self.roles = {}
        self.users = {}
        self.objects = {}

    def add_role(self, name, integrity_level):
        """Adds a role to the system."""
        if name not in self.roles:
            self.roles[name] = Role(name, integrity_level)
            print(f"Role '{name}' added with integrity level '{integrity_level}'.")

    def add_user(self, name, role_name):
        """Assigns a user to a role."""
        if role_name in self.roles:
            self.users[name] = User(name, self.roles[role_name])
            print(f"User '{name}' assigned to role '{role_name}'.")
        else:
            print(f"Error: Role '{role_name}' does not exist.")

    def add_object(self, name, integrity_level):
        """Adds an object to the system."""
        if name not in self.objects:
            self.objects[name] = Object(name, integrity_level)
            print(f"Object '{name}' added with integrity level '{integrity_level}'.")

    def grant_permission(self, role_name, obj_name, permission):
        """Grants a role permission for an object."""
        if role_name in self.roles and obj_name in self.objects:
            self.roles[role_name].grant_permission(self.objects[obj_name], permission)
            print(f"Granted '{permission}' permission to role '{role_name}' on '{obj_name}'.")
        else:
            print(f"Error: Invalid role '{role_name}' or object '{obj_name}'.")

    def revoke_permission(self, role_name, obj_name, permission):
        """Revokes a permission from a role for an object."""
        if role_name in self.roles and obj_name in self.objects:
            self.roles[role_name].revoke_permission(self.objects[obj_name], permission)
            print(f"Revoked '{permission}' permission from role '{role_name}' on '{obj_name}'.")

    def check_access(self, user_name, obj_name, permission):
        """Checks if a user can perform an action on an object."""
        if user_name not in self.users or obj_name not in self.objects:
            return f"Access Denied: Invalid user '{user_name}' or object '{obj_name}'."

        user = self.users[user_name]
        obj = self.objects[obj_name]

        if user.has_permission(obj, permission):
            return f"Access Granted: '{user_name}' can '{permission}' on '{obj_name}'."
        else:
            return f"Access Denied: '{user_name}' cannot '{permission}' on '{obj_name}' (Biba Model)."

    def display_roles(self):
        """Displays the roles and their permissions."""
        print("\nRole-Based Access Control with Integrity Levels:")
        for role in self.roles.values():
            print(f"\nRole: {role.name} (Integrity Level: {role.integrity_level})")
            for obj_name, permissions in role.permissions.items():
                print(f"  {obj_name}: {', '.join(permissions) if permissions else 'No Permissions'}")
        print("\n")


# Example Usage
acm = AccessControlSystem()

# Adding roles with integrity levels
acm.add_role("Admin", "High")
acm.add_role("Manager", "Medium")
acm.add_role("Employee", "Low")

# Adding objects with integrity levels
acm.add_object("Server1", "High")
acm.add_object("Database1", "Medium")
acm.add_object("HR_Files", "Low")

# Assigning users to roles
acm.add_user("Alice", "Admin")
acm.add_user("Bob", "Manager")
acm.add_user("Charlie", "Employee")

# Granting permissions
acm.grant_permission("Admin", "Server1", "read")
acm.grant_permission("Admin", "Server1", "write")
acm.grant_permission("Manager", "Database1", "read")
acm.grant_permission("Employee", "HR_Files", "read")

# Checking access
print(acm.check_access("Alice", "HR_Files", "read"))  # Denied (No Read Down)
print(acm.check_access("Bob", "Server1", "write"))  # Denied (No Write Up)
print(acm.check_access("Charlie", "HR_Files", "read"))  # Granted
print(acm.check_access("Bob", "Database1", "read"))  # Granted

# Displaying roles and permissions
acm.display_roles()
