```javascript
const users = [
  { id: 1, name: "Alice", age: 28, active: true },
  { id: 2, name: "Bob", age: 34, active: false },
  { id: 3, name: "Charlie", age: 22, active: true },
  { id: 4, name: "David", age: 41, active: true },
  { id: 5, name: "Emma", age: 31, active: false }
];

function getActiveUsers(list) {
  return list.filter(user => user.active);
}

function getAverageAge(list) {
  if (list.length === 0) return 0;

  const total = list.reduce((sum, user) => sum + user.age, 0);
  return total / list.length;
}

function findUserByName(list, name) {
  return list.find(
    user => user.name.toLowerCase() === name.toLowerCase()
  );
}

function createUser(name, age) {
  return {
    id: Date.now(),
    name,
    age,
    active: true
  };
}

function deactivateUser(list, id) {
  return list.map(user =>
    user.id === id ? { ...user, active: false } : user
  );
}

const activeUsers = getActiveUsers(users);
console.log("Active users:", activeUsers);

const averageAge = getAverageAge(users);
console.log("Average age:", averageAge);

const user = findUserByName(users, "Alice");
console.log("Found user:", user);

const newUser = createUser("Frank", 26);
console.log("New user:", newUser);

const updatedUsers = deactivateUser(users, 1);
console.log("Updated users:", updatedUsers);

const names = users.map(user => user.name);
console.log("Names:", names);

const adults = users.filter(user => user.age >= 30);
console.log("Users above 30:", adults);

const sortedUsers = [...users].sort((a, b) => a.age - b.age);
console.log("Sorted users:", sortedUsers);

const userSummary = users.map(user => ({
  name: user.name,
  status: user.active ? "Active" : "Inactive"
}));

console.log("Summary:", userSummary);
```
