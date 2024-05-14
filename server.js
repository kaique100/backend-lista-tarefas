const express = require('express');
const sqlite3 = require('sqlite3').verbose()
const cors = require('cors');

const app = express();
const PORT = 3000; // Defina a porta do servidor

const db = new sqlite3.Database('banco-de-dados.db')
app.use(cors());

// Criar a tabela 'tarefas' no banco de dados
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, task TEXT)");
});

app.use(express.json());

// Rota para adicionar uma nova tarefa
app.post('/tarefas', (req, res) => {
    const { task } = req.body;
    // Inserir a nova tarefa no banco de dados
    db.run("INSERT INTO tasks (task) VALUES (?)", [task], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, task });
    });
});

// Rota para obter todas as tarefas
app.get('/tarefas', (req, res) => {
    // Obter todas as tarefas do banco de dados
    db.all("SELECT * FROM tasks", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(rows);
    });
});

// Rota para obter uma tarefa específica
app.get('/tarefas/:id', (req, res) => {
    const { id } = req.params;
    // Obter a tarefa pelo ID
    db.get("SELECT * FROM tasks WHERE id = ?", [id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            res.status(200).json(row);
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Rota para editar uma tarefa existente
app.put('/tarefas/:id', (req, res) => {
    const { id } = req.params;
    const { task } = req.body;
    // Atualizar a tarefa com base no ID
    db.run("UPDATE tasks SET task = ? WHERE id = ?", [task, id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Tarefa atualizada com sucesso!' });
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Rota para excluir uma tarefa
app.delete('/tarefas/:id', (req, res) => {
    const { id } = req.params;
    // Excluir a tarefa com base no ID
    db.run("DELETE FROM tasks WHERE id = ?", [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Tarefa removida com sucesso!' });
        } else {
            res.status(404).json({ error: 'Tarefa não encontrada!' });
        }
    });
});

// Inicie o servidor Express
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});