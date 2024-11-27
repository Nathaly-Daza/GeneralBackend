<?php

namespace App\Http\Controllers;

use App\Models\Genders;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
class GenderController extends Controller
{
    public function index()
    {
        try {
            // Obtener todos los géneros de la base de datos
            $genders = Genders::all();

            // Devolver una respuesta JSON con los géneros obtenidos
            return response()->json([
                'status' => true,
                'data' => $genders
            ],200);
        } catch (\Throwable $th) {

            // Manejar cualquier excepción que pueda ocurrir durante la obtención de los géneros
            return response()->json([
             'status' => false,
             'message' => $th
            ],500);
        }
    }
    public function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'gen_name' => 'required|string|min:1|max:255|unique:genders|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Devolver una respuesta JSON con los errores de validación si falla la validación
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        }else{

            // Crear un nuevo registro de género con los datos proporcionados
            $gender = new Genders($request->input());
            $gender->save();

            //Disparar la acción de registro
            Controller::NewRegisterTrigger("Se creo un registro en la tabla genders: $request->gen_name ",3,$request->use_id);

            // Devolver una respuesta JSON indicando que se ha creado el género
            return response()->json([
                'status' => True,
                'message' => "The gender: ".$gender->gen_name." has been created."
            ],200);
        }
    }
    public function show($id)
    {

        // Buscar un género por su ID en la base de datos
        $gender = Genders::find($id);

        // Devolver un mensaje de error si no se encuentra el género solicitado
        if ($gender == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The gender requested was not found']
            ],400);
        }else{

            // Devolver una respuesta JSON con el género encontrado
            return response()->json([
                'status' => true,
                'data' => $gender
            ]);
        }
    }

    public function update(Request $request, $id)
    {

        // Buscar un género por su ID en la base de datos
        $gender = Genders::find($id);
        $gender_old = $gender->gen_name;
        if ($gender == null) {

            // Devolver un mensaje de error si no se encuentra el género solicitado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The gender requested was not found']
            ],400);
        }else{

            // Definir las reglas de validación para los datos de entrada
            $rules = [
                'gen_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Validar los datos de entrada con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si el nuevo nombre de género ya está registrado en la base de datos
            $validate = Controller::validate_exists($request->gen_name, 'genders', 'gen_name', 'gen_id', $id);

            // Devolver una respuesta JSON con los errores de validación si falla la validación o si el nombre del género ya está registrado
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            }else{

                // Actualizar el nombre del género con el nuevo valor proporcionado
                $gender->gen_name = $request->gen_name;
                $gender->save();

                // Disparar la acción de actualización
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla genders del dato: .$gender_old. con el dato: $request->gen_name",1,$request->use_id);

                // Devolver una respuesta JSON indicando que se ha actualizado el género
                return response()->json([
                    'status' => True,
                    'message' => "The gender: ".$gender->gen_name." has been update."
                ],200);
            }
        }
    }

    public function destroy(Genders $genders)
    {

        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ],400);
    }
}
