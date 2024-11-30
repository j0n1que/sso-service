package auth

import (
	"context"

	ssov1 "github.com/j0n1que/sso-protos/gen/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Auth interface {
	RegisterUser(ctx context.Context, login, password, telegramLogin string) error
	AuthorizeUser(ctx context.Context, login, password string) (string, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	ChangePassword(ctx context.Context, userID int64, newPassword string) error
	GetAllUsers(ctx context.Context) ([]*ssov1.User, error)
	GetUserByTelegram(ctx context.Context, telegramLogin string) ([]*ssov1.User, error)
	MakeAdmin(ctx context.Context, userID int64) error
	GetJWT(ctx context.Context, userID int64) (string, error)
	DeleteJWT(ctx context.Context, userID int64) error
}

type ServerAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &ServerAPI{auth: auth})
}

func (s *ServerAPI) RegisterNewUser(ctx context.Context, req *ssov1.RegisterRequest) (*emptypb.Empty, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}
	if err := s.auth.RegisterUser(ctx, req.GetLogin(), req.GetPassword(), req.GetTelegramLogin()); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}

func (s *ServerAPI) AuthorizeUser(ctx context.Context, req *ssov1.AutohrizeRequest) (*ssov1.AuthorizeResponse, error) {
	if err := validateAuth(req); err != nil {
		return nil, err
	}
	token, err := s.auth.AuthorizeUser(ctx, req.GetLogin(), req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.AuthorizeResponse{
		Token: token,
	}, nil
}

func (s *ServerAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *ServerAPI) ChangePassword(ctx context.Context, req *ssov1.ChangePasswordRequest) (*emptypb.Empty, error) {
	if err := validateChangePassword(req); err != nil {
		return nil, err
	}
	if err := s.auth.ChangePassword(ctx, req.GetUserId(), req.GetNewPassword()); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}

func (s *ServerAPI) GetAllUsers(ctx context.Context, req *emptypb.Empty) (*ssov1.ListOfUsers, error) {
	users, err := s.auth.GetAllUsers(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.ListOfUsers{
		Users: users,
	}, nil
}

func (s *ServerAPI) GetUserByTelegram(ctx context.Context, req *ssov1.GetUserByTelegramRequest) (*ssov1.ListOfUsers, error) {
	if err := validateGetUserByTelegram(req); err != nil {
		return nil, err
	}

	users, err := s.auth.GetUserByTelegram(ctx, req.GetTelegramLogin())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.ListOfUsers{
		Users: users,
	}, nil
}

func (s *ServerAPI) MakeAdmin(ctx context.Context, req *ssov1.MakeAdminRequest) (*emptypb.Empty, error) {
	if err := s.auth.MakeAdmin(ctx, req.GetUserId()); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}

func (s *ServerAPI) GetJWT(ctx context.Context, req *ssov1.GetJWTRequest) (*ssov1.GetJWTResponse, error) {
	token, err := s.auth.GetJWT(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.GetJWTResponse{
		Token: token,
	}, nil
}

func (s *ServerAPI) DeleteJWT(ctx context.Context, req *ssov1.DeleteJWTRequest) (*emptypb.Empty, error) {
	if err := s.auth.DeleteJWT(ctx, req.GetUserId()); err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &emptypb.Empty{}, nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetLogin() == "" {
		return status.Error(codes.InvalidArgument, "login is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateAuth(req *ssov1.AutohrizeRequest) error {
	if req.GetLogin() == "" {
		return status.Error(codes.InvalidArgument, "login is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateChangePassword(req *ssov1.ChangePasswordRequest) error {
	if req.GetNewPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateGetUserByTelegram(req *ssov1.GetUserByTelegramRequest) error {
	if req.GetTelegramLogin() == "" {
		return status.Error(codes.InvalidArgument, "telegram login is required")
	}
	return nil
}
