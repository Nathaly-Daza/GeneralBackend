<?php

namespace App\Http\Controllers;

use App\Models\Project;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class ProjectController extends Controller
{
    public function index()
    {
        try {
            // Seleccionar todos los proyectos desde la base de datos
            $projects = Project::select();

            // Retornar una respuesta JSON con los proyectos obtenidos
            return response()->json([
                'status' => true,
                'data' => $projects
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier error que ocurra y retornar una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => "Error occurred while found elements."
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'proj_name' => 'required|string|min:1|max:255|unique:projects|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'are_id' => 'required|integer|exists:areas',
            'use_id' =>'required|integer|exists:users'
        ];

        // Ejecutar el validador con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Verificar si la validación falla y retornar mensajes de error si es así
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Si la validación pasa, crear una nueva instancia de Project y guardarla en la base de datos
            $project = new Project($request->input());
            $project->save();

            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
            Controller::NewRegisterTrigger("Se creó un registro en la tabla Project: $request->proj_name, $request->are_id ", 3, $request->use_id);

            // Retornar una respuesta JSON indicando que el proyecto fue creado exitosamente
            return response()->json([
                'status' => true,
                'message' => "The project: " . $project->proj_name . " has been created."
            ], 200);
        }
    }
    public function show($id)
    {
        // Buscar el proyecto por su ID en la base de datos
        $project = Project::search($id);

        // Verificar si el proyecto no existe y retornar un mensaje de error si es así
        if ($project == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Project requested was not found']
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles del proyecto encontrado
            return response()->json([
                'status' => true,
                'data' => $project
            ]);
        }
    }

    public function update(Request $request, $id)
    {
        // Buscar el proyecto por su ID en la base de datos
        $project = Project::find($id);

        // Verificar si el proyecto no existe y retornar un mensaje de error si es así
        if ($project == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Project requested was not found']
            ], 400);
        } else {
            // Definir reglas de validación para los campos de entrada
            $rules = [
                'proj_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'are_id' => 'required|integer|exists:areas',
                'use_id' =>'required|integer|exists:users'
            ];

            // Ejecutar el validador con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si el proyecto con el mismo nombre ya existe en la base de datos
            $validate = Controller::validate_exists($request->proj_name, 'projects', 'proj_name', 'proj_id', $id);

            // Verificar si la validación falla o si ya existe un proyecto con el mismo nombre
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Si la validación pasa, actualizar el proyecto con los nuevos datos proporcionados
                $project->proj_name = $request->proj_name;
                $project->are_id = $request->are_id;
                $project->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("Se realizó una Edición de datos en la tabla Project del dato: $id con los datos: $request->proj_name, $request->are_id ", 4, $request->use_id);

                // Retornar una respuesta JSON indicando que el proyecto fue actualizado exitosamente
                return response()->json([
                    'status' => true,
                    'message' => "The project: " . $project->proj_name . " has been updated successfully."
                ], 200);
            }
        }
    }
    public function destroy(Project $projects)
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE."
        ], 400);
    }
}
