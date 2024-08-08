class AuthenticationController < ApplicationController
  # before_action :authorize_request, except: :login

  # POST /signup
  def signup
    user = User.new(user_params)
    if user.save
      render json: user, status: :created
      # I should log them in on sucessful signup
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  # POST /login
  def login
    Rails.logger.info 'In the login post'
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      token = encode_token(user_id: user.id)
      render json: { token: token, user: user }, status: :ok
    else
      render json: { errors: 'Invalid email or password' }, status: :unauthorized
    end
  end

  private

  def user_params
    params.permit(:email, :password)
  end

  def encode_token(payload)
    JWT.encode(payload, 'your_secret_key')
  end

  def authorize_request
    header = request.headers['Authorization']
    header = header.split(' ').last if header
    decoded = JWT.decode(header, 'your_secret_key')[0]
    @current_user = User.find(decoded['user_id'])
  rescue ActiveRecord::RecordNotFound, JWT::DecodeError
    render json: { errors: 'Unauthorized' }, status: :unauthorized
  end
end
