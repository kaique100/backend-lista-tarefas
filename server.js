const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000; // Defina a porta do servidor

app.use(express.json()); // Responsável por fazer o parse do corpo das requisições HTTP com formato JSON

let tarefas = [];

// Rota para adicionar uma nova tarefa
app.post('/tarefas', (req, res) => {
    const { tarefa } = req.body;
    tarefas.push({  id:tarefas.length + 1, tarefa });
    res.status(201).json({ message: 'Tarefa adicionada com sucesso!' });
});


// Rota para obter todas as tarefas
app.get('/tarefas/:id', (req, res) => {
    const { id } = req.params;
    const t = tarefas.find(t => t.id === parseInt(id));
    if (t) {
      res.status(200).json(t);
    } else {
      res.status(404).json({ error: 'Tarefa não encontrada!' });
    }
  });

// Rota para obter uma tarefas específica
app.get('/tarefas', (req, res) => {
    // Lógica para obter e retornar todas as tarefas do banco de dados
    res.status(200).json(tarefas);
});

// Rota para editar uma tarefa existente
app.put('/tarefas/:id', (req, res) => {
  // Lógica para obter e retornar todas as tarefas do banco de dados
  const {id} = req.params;
  const {tarefa} = req.body;
  const index = tarefas.findIndex(t => t.id === parseInt(id));

  if (index != -1) {
    tarefas[index].tarefa = tarefa;
    res.status(200).json({ message: 'Tarefa atualizada com sucesso!'})
  }else{
    res.status(404).json({error: 'Tarefa não encontrada!'});
  }
});

// Rota para excluir uma tarefa
app.delete('/tarefas/:id', (req, res) => { 
   const { id } = req.params;  
   const index = tarefas.findIndex(t => t.id === parseInt(id));  
   if (index !== -1) {    
    tarefas.splice(index, 1);    
    res.status(200).json({ message: 'Tarefa removida com sucesso!' });  
  } else {   
     res.status(404).json({ error: 'Tarefa não encontrada!' });  }});
// Inicie o servidor Express:
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta em http://localhost:${PORT}`);
});